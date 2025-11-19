package core

import (
	"bytes"
	"github.com/klauspost/compress/zstd"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"context"
	"net/http"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"go.uber.org/zap"
)

// RedirectToURL redirects the user and aborts the context.
func RedirectToURL(
	logger *zap.Logger,
	url string,
	wrt http.ResponseWriter,
	req *http.Request,
	statusCode int,
) context.Context {
	wrt.Header().Add(
		"Cache-Control",
		"no-cache, no-store, must-revalidate, max-age=0",
	)

	http.Redirect(wrt, req, url, statusCode)

	return RevokeProxy(logger, req)
}

func EncryptToken(
	scope *models.RequestScope,
	rawToken string,
	encKey string,
	tokenType string,
	writer http.ResponseWriter,
) (string, error) {
	var (
		err       error
		encrypted string
	)

	encrypted, err = encryption.EncodeText(rawToken, encKey)
	if err != nil {
		scope.Logger.Error(
			"failed to encrypt token",
			zap.Error(err),
			zap.String("type", tokenType),
		)
		writer.WriteHeader(http.StatusInternalServerError)

		return "", err
	}

	return encrypted, nil
}

// RevokeProxy is responsible for stopping middleware from proxying the request.
func RevokeProxy(logger *zap.Logger, req *http.Request) context.Context {
	var scope *models.RequestScope

	ctxVal := req.Context().Value(constant.ContextScopeName)

	switch ctxVal {
	case nil:
		scope = &models.RequestScope{AccessDenied: true}
	default:
		var assertOk bool

		scope, assertOk = ctxVal.(*models.RequestScope)
		if !assertOk {
			logger.Error(apperrors.ErrAssertionFailed.Error())

			scope = &models.RequestScope{AccessDenied: true}
		}
	}

	scope.AccessDenied = true

	return context.WithValue(req.Context(), constant.ContextScopeName, scope)
}

// CompressData compresses data using zstd
func CompressData(data []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(
		nil,
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression),
	)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()

	return encoder.EncodeAll(data, make([]byte, 0, len(data))), nil
}

// DecompressData decompresses zstd compressed data
func DecompressData(compressed []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	return decoder.DecodeAll(compressed, nil)
}

// CompressAndEncryptToken compresses then encrypts a token
// For JWT tokens, it decodes base64 first, compresses header+payload, keeps signature raw
func CompressAndEncryptToken(
	scope *models.RequestScope,
	rawToken string,
	encKey string,
	tokenType string,
	writer http.ResponseWriter,
) (string, error) {
	var (
		err       error
		encrypted string
	)

	// check if this is a JWT (contains exactly 2 dots)
	isJWT := strings.Count(rawToken, ".") == 2

	if isJWT {
		// decode JWT parts from base64 to get raw JSON
		parts := strings.Split(rawToken, ".")

		var decodedParts [][]byte

		for i, part := range parts {
			// JWT uses base64url encoding
			decoded, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				// fallback to standard base64
				decoded, err = base64.RawStdEncoding.DecodeString(part)
				if err != nil {
					scope.Logger.Warn(
						"failed to decode JWT part, using raw token",
						zap.Error(err),
						zap.String("type", tokenType),
						zap.Int("part", i),
					)
					// fallback to compressing the raw token
					isJWT = false
					break
				}
			}
			decodedParts = append(decodedParts, decoded)
		}

		if isJWT && len(decodedParts) == 3 {
			// compress only header + payload (parts 0 and 1)
			// signature (part 2) is random data and won't compress
			var compressibleData bytes.Buffer
			compressibleData.Write(decodedParts[0])
			compressibleData.Write(decodedParts[1])

			compressed, err := CompressData(compressibleData.Bytes())
			if err != nil {
				scope.Logger.Error(
					"failed to compress token",
					zap.Error(err),
					zap.String("type", tokenType),
				)
				writer.WriteHeader(http.StatusInternalServerError)
				return "", err
			}

			// build final structure: [len0][len1][len2][compressed(part0+part1)][raw part2]
			var finalData bytes.Buffer
			binary.Write(&finalData, binary.BigEndian, uint16(len(decodedParts[0])))
			binary.Write(&finalData, binary.BigEndian, uint16(len(decodedParts[1])))
			binary.Write(&finalData, binary.BigEndian, uint16(len(decodedParts[2])))
			finalData.Write(compressed)
			finalData.Write(decodedParts[2]) // raw signature

			compressibleSize := compressibleData.Len()
			compressedSize := len(compressed)
			signatureSize := len(decodedParts[2])
			finalSize := finalData.Len()

			scope.Logger.Debug(
				"JWT compression stats",
				zap.String("type", tokenType),
				zap.Int("original_base64_size", len(rawToken)),
				zap.Int("decoded_total_size", compressibleSize+signatureSize),
				zap.Int("compressible_size", compressibleSize),
				zap.Int("compressed_size", compressedSize),
				zap.Int("signature_size_raw", signatureSize),
				zap.Int("final_size_with_metadata", finalSize),
				zap.Float64("compression_ratio_percent", math.Round(float64(compressedSize)/float64(compressibleSize)*10000)/100),
				zap.Float64("overall_saving_percent", math.Round(float64(len(rawToken)-finalSize)/float64(len(rawToken))*10000)/100),
			)

			// encrypt the final data
			encrypted, err = encryption.EncodeCompressedData(finalData.Bytes(), encKey)
			if err != nil {
				scope.Logger.Error(
					"failed to encrypt compressed token",
					zap.Error(err),
					zap.String("type", tokenType),
				)
				writer.WriteHeader(http.StatusInternalServerError)
				return "", err
			}

			return encrypted, nil
		}
	}

	// not a JWT or decoding failed, compress as-is
	dataToCompress := []byte(rawToken)
	compressed, err := CompressData(dataToCompress)
	if err != nil {
		scope.Logger.Error(
			"failed to compress token",
			zap.Error(err),
			zap.String("type", tokenType),
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return "", err
	}

	originalSize := len(dataToCompress)
	compressedSize := len(compressed)
	ratio := float64(compressedSize) / float64(originalSize) * 100

	scope.Logger.Debug(
		"token compression stats (non-JWT)",
		zap.String("type", tokenType),
		zap.Int("original_size", originalSize),
		zap.Int("compressed_size", compressedSize),
		zap.Float64("compression_ratio_percent", ratio),
	)

	// encrypt the compressed token
	encrypted, err = encryption.EncodeCompressedData(compressed, encKey)
	if err != nil {
		scope.Logger.Error(
			"failed to encrypt compressed token",
			zap.Error(err),
			zap.String("type", tokenType),
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return "", err
	}

	return encrypted, nil
}

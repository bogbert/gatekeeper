package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/clientcredentials"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
)

const (
	testRealm               = "test"
	testClient              = "test-client"
	testClientSecret        = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
	pkceTestClient          = "test-client-pkce"
	pkceTestClientSecret    = "F2GqU40xwX0P2LrTvHUHqwNoSk4U4n5R"
	umaTestClient           = "test-client-uma"
	umaTestClientSecret     = "A5vokiGdI3H2r4aXFrANbKvn4R7cbf6P"
	timeout                 = time.Second * 300
	idpURI                  = "http://localhost:8081"
	testUser                = "myuser"
	testPass                = "baba1234"
	testPath                = "/test"
	umaAllowedPath          = "/pets"
	umaForbiddenPath        = "/pets/1"
	umaNonExistentPath      = "/cat"
	umaMethodAllowedPath    = "/horse"
	umaFwdMethodAllowedPath = "/turtle"
	postLoginRedirectPath   = "/post/login/path"
	pkceCookieName          = "TESTPKCECOOKIE"
)

var idpRealmURI = fmt.Sprintf("%s/realms/%s", idpURI, testRealm)

func generateRandomPort() string {
	rg := rand.New(rand.NewSource(time.Now().UnixNano()))
	min := 1024
	max := 65000
	return fmt.Sprintf("%d", rg.Intn(max-min+1)+min)
}

func startAndWait(portNum string, osArgs []string) {
	go func() {
		defer GinkgoRecover()
		app := proxy.NewOauthProxyApp()
		Expect(app.Run(osArgs)).To(Succeed())
	}()

	Eventually(func(g Gomega) error {
		conn, err := net.Dial("tcp", ":"+portNum)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}, timeout, 15*time.Second).Should(Succeed())
}

func codeFlowLogin(client *resty.Client, reqAddress string, expStatusCode int) *resty.Response {
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	resp, err := client.R().Get(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(http.StatusOK))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	Expect(err).NotTo(HaveOccurred())

	selection := doc.Find("#kc-form-login")
	Expect(selection).ToNot(BeNil())

	selection.Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		Expect(exists).To(BeTrue())

		client.FormData.Add("username", testUser)
		client.FormData.Add("password", testPass)
		resp, err = client.R().Post(action)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(expStatusCode))
	})

	return resp
}

var _ = Describe("NoRedirects Simple login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--enable-default-deny=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with service account and logout successfully",
			Label("api_flow"),
			Label("basic_case"),
			func(ctx context.Context) {
				conf := &clientcredentials.Config{
					ClientID:     testClient,
					ClientSecret: testClientSecret,
					Scopes:       []string{"email", "openid"},
					TokenURL:     idpRealmURI + constant.IdpTokenURI,
				}

				respToken, err := conf.Token(ctx)
				Expect(err).NotTo(HaveOccurred())

				request := resty.New().SetRedirectPolicy(
					resty.NoRedirectPolicy()).R().SetAuthToken(respToken.AccessToken)
				resp, err := request.Get(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				request = resty.New().R().SetAuthToken(respToken.AccessToken)
				resp, err = request.Get(proxyAddress + "/oauth/logout")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			},
		)
	})
})

var _ = Describe("Code Flow login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--enable-idp-session-check=false",
			"--enable-default-deny=false",
			"--resources=uri=/*|roles=uma_authorization,user",
			"--openid-provider-retry-count=30",
			"--enable-refresh-tokens=true",
			"--encryption-key=sdkljfalisujeoir",
			"--secure-cookie=false",
			"--post-login-redirect-path=" + postLoginRedirectPath,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Performing standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow"),
			Label("basic_case"),
			func(ctx context.Context) {
				var err error
				rClient := resty.New()
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieLogin string
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("wait for access token expiration")
				time.Sleep(32 * time.Second)
				resp, err = rClient.R().Get(proxyAddress + "/any")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), "/any")).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(err).NotTo(HaveOccurred())
				cookiesAfterRefresh := rClient.GetClient().Jar.Cookies(jarURI)

				var accessCookieAfterRefresh string
				for _, cook := range cookiesAfterRefresh {
					if cook.Name == constant.AccessCookie {
						accessCookieLogin = cook.Value
					}
				}

				By("check if access token cookie has changed")
				Expect(accessCookieLogin).NotTo(Equal(accessCookieAfterRefresh))

				By("make another request with new access token")
				resp, err = rClient.R().Get(proxyAddress + "/any")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body = resp.Body()
				Expect(strings.Contains(string(body), "/any")).To(BeTrue())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})

	When("Using forged expired access token with valid refresh token", func() {
		It("should be forbidden",
			Label("code_flow"),
			Label("forged_access_token"),
			Label("attack"),
			func(ctx context.Context) {
				var err error
				rClient := resty.New()
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
				body := resp.Body()
				Expect(strings.Contains(string(body), postLoginRedirectPath)).To(BeTrue())
				jarURI, err := url.Parse(proxyAddress)
				Expect(err).NotTo(HaveOccurred())
				cookiesLogin := rClient.GetClient().Jar.Cookies(jarURI)

				tok := testsuite.NewTestToken("example")
				tok.SetExpiration(time.Now().Add(-5 * time.Minute))
				unsignedToken, err := tok.GetUnsignedToken()
				Expect(err).NotTo(HaveOccurred())

				badlySignedToken := unsignedToken + testsuite.FakeSignature
				for _, cook := range cookiesLogin {
					if cook.Name == constant.AccessCookie {
						cook.Value = badlySignedToken
					}
				}

				rClient.GetClient().Jar.SetCookies(jarURI, cookiesLogin)

				By("make another request with forged access token")
				resp, err = rClient.R().Get(proxyAddress + "/any")
				Expect(err).NotTo(HaveOccurred())
				Expect(strings.Contains(string(body), "/any")).To(BeFalse())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))

				By("log out")
				resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			},
		)
	})
})

var _ = Describe("Code Flow PKCE login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Peforming standard login", func() {
		It("should login with user/password and logout successfully",
			Label("code_flow"),
			Label("pkce"),
			func(ctx context.Context) {
				var err error
				rClient := resty.New()
				resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
				Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

				body := resp.Body()
				Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())

				resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))

				rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
				resp, _ = rClient.R().Get(proxyAddress)
				Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
			},
		)
	})
})

var _ = Describe("Code Flow login/logout with session check", func() {
	var portNum string
	var proxyAddressFirst string
	var proxyAddressSec string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddressFirst = "http://127.0.0.1:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-idp-session-check=true",
			"--enable-logout-redirect=true",
			"--enable-id-token-cookie=true",
			"--post-logout-redirect-uri=http://google.com",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)

		portNum = generateRandomPort()
		proxyAddressSec = "http://localhost:" + portNum
		osArgs = []string{os.Args[0]}
		proxyArgs = []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
			"--enable-idp-session-check=true",
			"--enable-logout-redirect=true",
			"--enable-id-token-cookie=true",
			"--post-logout-redirect-uri=http://google.com",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Login user with one browser client on two clients/app and logout on one of them", func() {
		It("should logout on both successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddressFirst, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
			resp = codeFlowLogin(rClient, proxyAddressSec, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			resp, err = rClient.R().Get(proxyAddressFirst + testPath)
			Expect(err).NotTo(HaveOccurred())
			body := resp.Body()
			Expect(strings.Contains(string(body), testPath)).To(BeTrue())

			resp, err = rClient.R().Get(proxyAddressSec + testPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			body = resp.Body()
			Expect(strings.Contains(string(body), testPath)).To(BeTrue())

			By("Logout user on first client")
			resp, err = rClient.R().Get(proxyAddressFirst + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			By("Verify logged out on second client")
			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddressSec)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))

			By("Verify logged out on first client")
			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddressFirst)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})
})

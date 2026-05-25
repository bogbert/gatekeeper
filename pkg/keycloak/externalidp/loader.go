package externalidp

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LoadUsersFromFile loads and parses the users JSON file.
func LoadUsersFromFile(filePath string) (*UsersData, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read users file: %w", err)
	}

	var usersData UsersData
	if err := json.Unmarshal(data, &usersData); err != nil {
		return nil, fmt.Errorf("failed to parse users JSON: %w", err)
	}

	return &usersData, nil
}

// GetFileModTime returns the modification time of the file.
func GetFileModTime(filePath string) (time.Time, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to stat file: %w", err)
	}

	return info.ModTime(), nil
}

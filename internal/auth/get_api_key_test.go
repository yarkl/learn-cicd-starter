package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Succesful key retrieval",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key-123"}},
			expectedKey:   "my-secret-key-123",
			expectedError: nil,
		},
		{
			name:          "Authorization header is absent",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Authorization header is empty",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Неверный префикс (например, Bearer)",
			headers:       http.Header{"Authorization": []string{"Bearer some-token"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Only prefix without key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Header key is case sensitive",
			headers:       http.Header{"Authorization": []string{"apikey mykey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Checking key
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}

			// Cheking for errors
			if tt.expectedError == nil {
				if err != nil {
					t.Fatalf("No error expected, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected erorr %v, got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
				}
			}
		})
	}
}

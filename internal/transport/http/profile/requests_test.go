package profile

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func strPtr(s string) *string { return &s }

func TestUpdateProfileRequest_Validate(t *testing.T) {
	validAvatar := uuid.New().String()

	tests := []struct {
		name string
		req  UpdateProfileRequest
		want map[string]string // field -> expected error code
	}{
		{
			name: "valid, no avatar",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: "Doe"},
			want: map[string]string{},
		},
		{
			name: "valid, with avatar",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: "Doe", Avatar: strPtr(validAvatar)},
			want: map[string]string{},
		},
		{
			name: "valid, avatar explicitly cleared",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: "Doe", Avatar: strPtr("")},
			want: map[string]string{},
		},
		{
			name: "empty first name",
			req:  UpdateProfileRequest{FirstName: "", LastName: "Doe"},
			want: map[string]string{"firstName": CodeFirstNameRequired},
		},
		{
			name: "whitespace-only first name",
			req:  UpdateProfileRequest{FirstName: "   ", LastName: "Doe"},
			want: map[string]string{"firstName": CodeFirstNameRequired},
		},
		{
			name: "empty last name",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: ""},
			want: map[string]string{"lastName": CodeLastNameRequired},
		},
		{
			name: "first name too long",
			req:  UpdateProfileRequest{FirstName: strings.Repeat("a", maxFirstNameLength+1), LastName: "Doe"},
			want: map[string]string{"firstName": CodeFirstNameTooLong},
		},
		{
			name: "last name too long",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: strings.Repeat("a", maxLastNameLength+1)},
			want: map[string]string{"lastName": CodeLastNameTooLong},
		},
		{
			name: "malformed avatar",
			req:  UpdateProfileRequest{FirstName: "Jane", LastName: "Doe", Avatar: strPtr("not-a-uuid")},
			want: map[string]string{"avatar": CodeAvatarInvalid},
		},
		{
			name: "everything invalid",
			req:  UpdateProfileRequest{FirstName: "", LastName: "", Avatar: strPtr("not-a-uuid")},
			want: map[string]string{
				"firstName": CodeFirstNameRequired,
				"lastName":  CodeLastNameRequired,
				"avatar":    CodeAvatarInvalid,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.Validate()

			if len(got) != len(tt.want) {
				t.Fatalf("Validate() = %v, want %v", got, tt.want)
			}
			for field, wantCode := range tt.want {
				if gotCode, ok := got[field]; !ok || gotCode != wantCode {
					t.Errorf("field %q: got code %q, want %q", field, gotCode, wantCode)
				}
			}
		})
	}
}

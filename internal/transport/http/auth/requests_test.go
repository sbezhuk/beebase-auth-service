package auth

import "testing"

func TestRegisterRequest_Validate(t *testing.T) {
	tests := []struct {
		name string
		req  RegisterRequest
		want map[string]string // field -> expected error code
	}{
		{
			name: "valid",
			req:  RegisterRequest{Email: "bee@example.com", Password: "supersecret"},
			want: map[string]string{},
		},
		{
			name: "empty email",
			req:  RegisterRequest{Email: "", Password: "supersecret"},
			want: map[string]string{"email": CodeEmailRequired},
		},
		{
			name: "malformed email",
			req:  RegisterRequest{Email: "not-an-email", Password: "supersecret"},
			want: map[string]string{"email": CodeEmailInvalid},
		},
		{
			name: "short password",
			req:  RegisterRequest{Email: "bee@example.com", Password: "short"},
			want: map[string]string{"password": CodePasswordTooShort},
		},
		{
			name: "both invalid",
			req:  RegisterRequest{Email: "bad", Password: "short"},
			want: map[string]string{"email": CodeEmailInvalid, "password": CodePasswordTooShort},
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

func TestLoginRequest_Validate(t *testing.T) {
	if fields := (&LoginRequest{Email: "bee@example.com", Password: "x"}).Validate(); len(fields) != 0 {
		t.Errorf("expected no errors, got %v", fields)
	}

	fields := (&LoginRequest{Email: "bee@example.com", Password: ""}).Validate()
	if code := fields["password"]; code != CodePasswordRequired {
		t.Errorf("password code = %q, want %q", code, CodePasswordRequired)
	}

	fields = (&LoginRequest{Email: "not-an-email", Password: "x"}).Validate()
	if code := fields["email"]; code != CodeEmailInvalid {
		t.Errorf("email code = %q, want %q", code, CodeEmailInvalid)
	}
}

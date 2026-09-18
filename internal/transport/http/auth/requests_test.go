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
			req:  RegisterRequest{Email: "bee@example.com", Password: "supersecret1!"},
			want: map[string]string{},
		},
		{
			name: "empty email",
			req:  RegisterRequest{Email: "", Password: "supersecret1!"},
			want: map[string]string{"email": CodeEmailRequired},
		},
		{
			name: "malformed email",
			req:  RegisterRequest{Email: "not-an-email", Password: "supersecret1!"},
			want: map[string]string{"email": CodeEmailInvalid},
		},
		{
			name: "short password",
			req:  RegisterRequest{Email: "bee@example.com", Password: "sh0rt!"},
			want: map[string]string{"password": CodePasswordTooShort},
		},
		{
			name: "password missing digit",
			req:  RegisterRequest{Email: "bee@example.com", Password: "supersecret!"},
			want: map[string]string{"password": CodePasswordMissingDigit},
		},
		{
			name: "password missing special char",
			req:  RegisterRequest{Email: "bee@example.com", Password: "supersecret1"},
			want: map[string]string{"password": CodePasswordMissingSpecialChar},
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

func TestChangePasswordRequest_Validate(t *testing.T) {
	tests := []struct {
		name string
		req  ChangePasswordRequest
		want map[string]string // field -> expected error code
	}{
		{
			name: "valid",
			req:  ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "supersecret1!", OTP: "123456"},
			want: map[string]string{},
		},
		{
			name: "missing current password",
			req:  ChangePasswordRequest{CurrentPassword: "", NewPassword: "supersecret1!", OTP: "123456"},
			want: map[string]string{"currentPassword": CodeCurrentPasswordRequired},
		},
		{
			name: "new password too short",
			req:  ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "sh0rt!", OTP: "123456"},
			want: map[string]string{"newPassword": CodePasswordTooShort},
		},
		{
			name: "new password missing digit",
			req:  ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "supersecret!", OTP: "123456"},
			want: map[string]string{"newPassword": CodePasswordMissingDigit},
		},
		{
			name: "new password missing special char",
			req:  ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "supersecret1", OTP: "123456"},
			want: map[string]string{"newPassword": CodePasswordMissingSpecialChar},
		},
		{
			name: "invalid otp",
			req:  ChangePasswordRequest{CurrentPassword: "old-password", NewPassword: "supersecret1!", OTP: "abc"},
			want: map[string]string{"otp": CodeOTPInvalidFormat},
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

func TestPasswordResetConfirmRequest_Validate(t *testing.T) {
	tests := []struct {
		name string
		req  PasswordResetConfirmRequest
		want map[string]string // field -> expected error code
	}{
		{
			name: "valid",
			req:  PasswordResetConfirmRequest{ResetToken: "token", NewPassword: "supersecret1!", ConfirmPassword: "supersecret1!"},
			want: map[string]string{},
		},
		{
			name: "missing reset token",
			req:  PasswordResetConfirmRequest{ResetToken: "", NewPassword: "supersecret1!", ConfirmPassword: "supersecret1!"},
			want: map[string]string{"resetToken": CodeResetTokenRequired},
		},
		{
			name: "new password too short",
			req:  PasswordResetConfirmRequest{ResetToken: "token", NewPassword: "sh0rt!", ConfirmPassword: "sh0rt!"},
			want: map[string]string{"newPassword": CodePasswordTooShort},
		},
		{
			name: "new password missing digit",
			req:  PasswordResetConfirmRequest{ResetToken: "token", NewPassword: "supersecret!", ConfirmPassword: "supersecret!"},
			want: map[string]string{"newPassword": CodePasswordMissingDigit},
		},
		{
			name: "new password missing special char",
			req:  PasswordResetConfirmRequest{ResetToken: "token", NewPassword: "supersecret1", ConfirmPassword: "supersecret1"},
			want: map[string]string{"newPassword": CodePasswordMissingSpecialChar},
		},
		{
			name: "confirm password mismatch",
			req:  PasswordResetConfirmRequest{ResetToken: "token", NewPassword: "supersecret1!", ConfirmPassword: "different1!"},
			want: map[string]string{"confirmPassword": CodeConfirmPasswordMismatch},
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

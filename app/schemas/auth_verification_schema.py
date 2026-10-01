from marshmallow import fields, validate, validates

from app.schemas.auth_account_schema import (
	CleanedSchema,
	EmailValidatedSchema,
	PasswordValidatedSchema,
)


class ForgotPasswordSchema(EmailValidatedSchema):
	email = fields.Str(required=True)


class ResetPasswordSchema(PasswordValidatedSchema):
	token = fields.Str(required=True)
	password = fields.Str(required=True, validate=validate.Length(min=8, max=128))

	@validates("password")
	def validate_password(self, value, **kwargs):
		PasswordValidatedSchema.validate_password(value)


class VerifyEmailSchema(CleanedSchema):
	token = fields.Str(required=True, validate=validate.Length(min=10, max=255))


class ResendVerificationSchema(EmailValidatedSchema):
	email = fields.Str(required=True)


class VerifyEmailOtpSchema(EmailValidatedSchema):
	email = fields.Str(required=True)
	otp = fields.Str(
		required=True,
		validate=[
			validate.Length(equal=6, error="OTP must be exactly 6 digits."),
			validate.Regexp(r"^\d{6}$", error="OTP must contain numbers only."),
		],
	)


class ResendEmailOtpSchema(EmailValidatedSchema):
	email = fields.Str(required=True)


forgot_password_schema = ForgotPasswordSchema()
reset_password_schema = ResetPasswordSchema()
verify_email_schema = VerifyEmailSchema()
resend_verification_schema = ResendVerificationSchema()
verify_email_otp_schema = VerifyEmailOtpSchema()
resend_email_otp_schema = ResendEmailOtpSchema()
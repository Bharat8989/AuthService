from marshmallow import ValidationError, fields, validate, validates

from app.schemas.auth_account_schema import (
	EmailValidatedSchema,
	PasswordValidatedSchema,
)
from app.security import validate_phone_format


class UpdateProfileSchema(EmailValidatedSchema):
	name = fields.Str(required=False, validate=validate.Length(min=2, max=255))
	email = fields.Str(required=False, validate=validate.Length(max=255))
	phone = fields.Str(required=False, allow_none=True, validate=validate.Length(min=7, max=20))

	@validates("phone")
	def validate_phone(self, value, **kwargs):
		valid, message = validate_phone_format(value)
		if not valid:
			raise ValidationError(message)


class ChangePasswordSchema(PasswordValidatedSchema):
	current_password = fields.Str(required=True)
	new_password = fields.Str(required=True, validate=validate.Length(min=8, max=128))

	@validates("new_password")
	def validate_new_password(self, value, **kwargs):
		PasswordValidatedSchema.validate_password(value)


update_profile_schema = UpdateProfileSchema()
change_password_schema = ChangePasswordSchema()
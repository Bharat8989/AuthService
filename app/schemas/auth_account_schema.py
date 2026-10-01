import re

from marshmallow import EXCLUDE, Schema, ValidationError, fields, pre_load, validate, validates

from app.security import validate_email_format, validate_phone_format


class CleanedSchema(Schema):
	class Meta:
		unknown = EXCLUDE

	@pre_load
	def normalize_text_fields(self, data, **kwargs):
		if not isinstance(data, dict):
			return data
		cleaned = dict(data)
		for key, value in cleaned.items():
			if isinstance(value, str) and key in {
				"name", "owner_name", "company_name", "email", "phone", "address", "otp"
			}:
				cleaned[key] = value.strip()
		if isinstance(cleaned.get("email"), str):
			cleaned["email"] = cleaned["email"].lower()
		return cleaned



class EmailValidatedSchema(CleanedSchema):
	@validates("email")
	def validate_email(self, value, **kwargs):
		valid, message = validate_email_format(value)
		if not valid:
			raise ValidationError(message)


class PasswordValidatedSchema(CleanedSchema):
	@staticmethod
	def validate_password(value):
		if not 8 <= len(value) <= 128:
			raise ValidationError("Password must be between 8 and 128 characters.")
		if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
			raise ValidationError("Password must contain at least one letter and one number.")


class RegisterTenantSchema(EmailValidatedSchema, PasswordValidatedSchema):
	name = fields.Str(required=True, validate=validate.Length(min=2, max=255))
	email = fields.Str(required=True, validate=validate.Length(max=255))
	phone = fields.Str(required=True, allow_none=True, validate=validate.Length(min=7, max=20))
	password = fields.Str(required=True, validate=validate.Length(min=8, max=128))

	@validates("phone")
	def validate_phone(self, value, **kwargs):
		valid, message = validate_phone_format(value)
		if not valid:
			raise ValidationError(message)

	@validates("password")
	def validate_password(self, value, **kwargs):
		PasswordValidatedSchema.validate_password(value)


class RegisterClientSchema(RegisterTenantSchema):
	name = fields.Str(required=False, load_default=None)
	company_name = fields.Str(required=True, validate=validate.Length(min=2, max=255))
	owner_name = fields.Str(required=True, validate=validate.Length(min=2, max=255))
	email = fields.Str(required=True, validate=validate.Length(max=255))
	address = fields.Str(required=False, allow_none=True, validate=validate.Length(max=500))


class LoginSchema(EmailValidatedSchema):
	email = fields.Str(required=True)
	password = fields.Str(required=True)


register_tenant_schema = RegisterTenantSchema()
register_client_schema = RegisterClientSchema()
login_schema = LoginSchema()
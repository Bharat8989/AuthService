from flask import jsonify


def success_response(data=None, message="Operation successful", status_code=200):
    body = {"success": True, "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code


def error_response(
    message="An error occurred",
    error_code="INTERNAL_ERROR",
    status_code=500,
    details=None,
):
    body = {"success": False, "message": message, "error_code": error_code}
    if details:
        body["details"] = details
    return jsonify(body), status_code


def validation_error_response(errors, message="Validation failed", status_code=422):
    return jsonify({"success": False, "message": message, "errors": errors}), status_code
from datetime import datetime
from flask import jsonify


# Helper function to format response messages for both success and error cases
def message_response(message, status_code, **kwargs):
    return jsonify({
        'message': message,
        'date': datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'),
        'status_code': status_code,
        **kwargs  # Unpack additional key-value pairs directly here
    }), status_code

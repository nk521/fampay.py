"""
login:

Flutter side call chain:
  PhoneNumberInputController._generateSession
    -> getPublicKey (host keystore), Uuid().v7() session_id
    -> AuthenticationRepository.createGenerateSession
       -> Dart's dio POST {enterstellar}/api/v1/login/session/
    -> signature interceptor wraps it (x-signature of url+body64+ts+cert+ua)

Response model GenerateAuthenticationSessionResponse (kryptonite/features/authentication/data/models/responses/generate_authentication_session_response.dart):
  contains at least: session_id, otp details (delivery channel, length, expiry)
  per _$GenerateAuthenticationSessionResponseFromJson.

You get the verification message with a list of VMNs:

SUCCESS: {'method': 'sim_binding', 'data': {'sim_binding_sessions':
[{'vmns': ['+91...', '...'], 'sms_token': 'YESPRODUPI pp... ...',
'providers': ['...', '...']}], 'expiry_timestamp': ..., ...}}

Sending the SMS to any VMN should grant us access.

"""

from fampay.constants import FamAppConsts

assert FamAppConsts.VERSION_CODE == "2602003"

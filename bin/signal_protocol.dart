import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:signal_protocol/signal_protocol.dart' as signal_protocol;

void main(List<String> arguments) async {
  /// ALICE
  Map<String, dynamic> alice = await signal_protocol.install('ALICE');

  /// BOB
  Map<String, dynamic> bob = await signal_protocol.install('BOB');

  /// ALICE : creating session and encrypting message Text
  final cipher = await signal_protocol.createEncryptionSession(
    address: signal_protocol.aliceAddress,
    deviceId: signal_protocol.aliceDeviceId,
    sessionStore: alice['session_store'],
    preKeyStore: alice['prekey_store'],
    signedPreKeyStore: alice['signed_prekey_store'],
    identityStore: alice['identity_store'],
    retrievedPreKey: PreKeyBundle(
      bob['registration_id'],
      signal_protocol.bobDeviceId,
      (bob['prekeys'] as List<PreKeyRecord>).first.id,
      Curve.decodePoint(DjbECPublicKey((bob['prekeys'] as List<PreKeyRecord>).first.getKeyPair().publicKey.serialize()).serialize(), 1),
      (bob['signed_prekey'] as SignedPreKeyRecord).id,
      Curve.decodePoint(DjbECPublicKey((bob['signed_prekey'] as SignedPreKeyRecord).getKeyPair().publicKey.serialize()).serialize(), 1),
      (bob['signed_prekey'] as SignedPreKeyRecord).signature,
      IdentityKey(Curve.decodePoint(DjbECPublicKey((bob['identity_pair'] as IdentityKeyPair).getPublicKey().serialize()).serialize(), 1)),
    ),
    message: 'Hello world',
  );

  print(cipher);
  final prekey = (bob['prekeys'] as List<PreKeyRecord>)
      .first
      .getKeyPair()
      .publicKey
      .serialize();
  print(prekey);
  print(Curve.decodePoint(DjbECPublicKey(prekey).serialize(), 1).serialize());

  /// BOB : creating session and decrypting cipher Text
  final message = await signal_protocol.createDecryptionSession(
    address: signal_protocol.bobAddress,
    deviceId: signal_protocol.bobDeviceId,
    sessionStore: bob['session_store'],
    preKeyStore: bob['prekey_store'],
    signedPreKeyStore: bob['signed_prekey_store'],
    identityStore: bob['identity_store'],
    retrievedPreKey: PreKeyBundle(
      alice['registration_id'],
      signal_protocol.aliceDeviceId,
      (alice['prekeys'] as List<PreKeyRecord>).last.id,
      (alice['prekeys'] as List<PreKeyRecord>).last.getKeyPair().publicKey,
      (alice['signed_prekey'] as SignedPreKeyRecord).id,
      (alice['signed_prekey'] as SignedPreKeyRecord).getKeyPair().publicKey,
      (alice['signed_prekey'] as SignedPreKeyRecord).signature,
      (alice['identity_pair'] as IdentityKeyPair).getPublicKey(),
    ),
    cipher: cipher,
  );

  print(message);
}

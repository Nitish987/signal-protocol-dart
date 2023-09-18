import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';

const aliceDeviceId = 1;
const bobDeviceId = 2;
const aliceAddress = 'alice';
const bobAddress = 'bob';

Future<Map<String, dynamic>> install(name) async {
  print(name);

  final identityKeyPair = generateIdentityKeyPair();
  print(identityKeyPair);

  final registrationId = generateRegistrationId(false);
  print(registrationId);

  final preKeys = generatePreKeys(0, 110);
  print(preKeys);

  final signedPreKey = generateSignedPreKey(identityKeyPair, 0);
  print(signedPreKey);

  final sessionStore = InMemorySessionStore();
  final preKeyStore = InMemoryPreKeyStore();
  final signedPreKeyStore = InMemorySignedPreKeyStore();
  final identityStore =
      InMemoryIdentityKeyStore(identityKeyPair, registrationId);

  for (var p in preKeys) {
    await preKeyStore.storePreKey(p.id, p);
  }
  await signedPreKeyStore.storeSignedPreKey(signedPreKey.id, signedPreKey);

  return {
    'identity_pair': identityKeyPair,
    'registration_id': registrationId,
    'prekeys': preKeys,
    'signed_prekey': signedPreKey,
    'session_store': sessionStore,
    'prekey_store': preKeyStore,
    'signed_prekey_store': signedPreKeyStore,
    'identity_store': identityStore,
  };
}

Future<String> createEncryptionSession(
    {address,
    deviceId,
    sessionStore,
    preKeyStore,
    signedPreKeyStore,
    identityStore,
    retrievedPreKey,
    message}) async {
  final remoteAddress = SignalProtocolAddress(address, deviceId);
  final sessionBuilder = SessionBuilder(sessionStore, preKeyStore,
      signedPreKeyStore, identityStore, remoteAddress);

  await sessionBuilder.processPreKeyBundle(retrievedPreKey);

  final sessionCipher = SessionCipher(sessionStore, preKeyStore,
      signedPreKeyStore, identityStore, remoteAddress);
  final ciphertext =
      await sessionCipher.encrypt(utf8.encode(message) as Uint8List);

  return String.fromCharCodes(ciphertext.serialize());
}

Future<String> createDecryptionSession(
    {address,
    deviceId,
    sessionStore,
    preKeyStore,
    signedPreKeyStore,
    identityStore,
    retrievedPreKey,
    cipher}) async {
  final remoteAddress = SignalProtocolAddress(address, deviceId);
  final sessionBuilder = SessionBuilder(sessionStore, preKeyStore,
      signedPreKeyStore, identityStore, remoteAddress);

  await sessionBuilder.processPreKeyBundle(retrievedPreKey);

  final sessionCipher = SessionCipher(sessionStore, preKeyStore,
      signedPreKeyStore, identityStore, remoteAddress);
  final messageText = await sessionCipher.decrypt(PreKeySignalMessage(
    Uint8List.fromList((cipher as String).codeUnits),
  ));

  return String.fromCharCodes(messageText);
}

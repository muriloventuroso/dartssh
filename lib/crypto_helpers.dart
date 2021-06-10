import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/secure_random_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

Future<crypto.SimpleKeyPair> keyPair_fromSecretKey(Uint8List? secretKey) async {
    final algorithm = crypto.Ed25519();
    final kp = await algorithm.newKeyPair();
    Uint8List pk = Uint8List.fromList((await kp.extractPublicKey()).bytes);
    Uint8List sk = Uint8List.fromList((await kp.extractPrivateKeyBytes()));

    // copy sk
    for (int i = 0; i < sk.length; i++){
      sk[i] = secretKey![i];
    }

    // copy pk from sk
    for (int i = 0; i < pk.length; i++){
      pk[i] = secretKey![32 + i]; // hard-copy
    }
      

    return crypto.SimpleKeyPairData(
      List<int>.unmodifiable(sk),
      type: crypto.KeyPairType.ed25519,
      publicKey: crypto.SimplePublicKey(pk, type: crypto.KeyPairType.ed25519),
    );
  }


/// An implementation of [SecureRandom] that return numbers in growing sequence.
class NullSecureRandom extends SecureRandomBase {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(SecureRandom, "Null", () => NullSecureRandom());

  var _nextValue = 0;

  String get algorithmName => "Null";

  void seed(CipherParameters params) {}

  int nextUint8() => clip8(_nextValue++);
}
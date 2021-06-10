// Copyright 2019 dartssh developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:dartssh/crypto_helpers.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';
import 'package:cryptography/cryptography.dart' as crypto;

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/ssh.dart';

class Identity {
  crypto.SimpleKeyPair? ed25519;
  int? ecdsaKeyType;
  ECPublicKey? ecdsaPublic;
  ECPrivateKey? ecdsaPrivate;
  asymmetric.RSAPublicKey? rsaPublic;
  asymmetric.RSAPrivateKey? rsaPrivate;

  Future<Ed25519Key> getEd25519PublicKey() async => Ed25519Key((await ed25519!.extractPublicKey()).bytes as Uint8List?);

  Future<Ed25519Signature> signWithEd25519Key(Uint8List m) async {
    final algorithm = crypto.Ed25519();
    final signature = await algorithm.sign(
      m,
      keyPair: ed25519!,
    );
    return Ed25519Signature(signature.bytes as Uint8List?);
  }
      

  ECDSAKey getECDSAPublicKey() => ECDSAKey(Key.name(ecdsaKeyType),
      Key.ellipticCurveName(ecdsaKeyType), ecdsaPublic!.Q!.getEncoded(false));

  ECDSASignature signWithECDSAKey(Uint8List m, SecureRandom secureRandom) {
    ECDSASigner signer = ECDSASigner(Key.ellipticCurveHash(ecdsaKeyType));
    signer.init(
        true,
        ParametersWithRandom(
          PrivateKeyParameter(ecdsaPrivate!),
          secureRandom,
        ));
    ECSignature sig = signer.generateSignature(m) as ECSignature;
    return ECDSASignature(Key.name(ecdsaKeyType), sig.r, sig.s);
  }

  RSAKey getRSAPublicKey() => RSAKey(rsaPublic!.exponent, rsaPublic!.modulus);

  RSASignature signWithRSAKey(Uint8List m) {
    RSASigner signer = RSASigner(SHA1Digest(), '06052b0e03021a');
    signer.init(
        true, PrivateKeyParameter<asymmetric.RSAPrivateKey>(rsaPrivate!));
    return RSASignature(signer.generateSignature(m).bytes);
  }

  Future<Uint8List> getRawPublicKey(int keyType) async {
    if (Key.ellipticCurveDSA(keyType)) return getECDSAPublicKey().toRaw();
    switch (keyType) {
      case Key.ED25519:
        return (await getEd25519PublicKey()).toRaw();
      case Key.RSA:
        return getRSAPublicKey().toRaw();
      default:
        throw FormatException('key type $keyType');
    }
  }

  Future<Uint8List> signMessage(int keyType, Uint8List? m, [SecureRandom? secureRandom]) async {
    if (Key.ellipticCurveDSA(keyType)) {
      return signWithECDSAKey(m!, secureRandom!).toRaw();
    }
    switch (keyType) {
      case Key.ED25519:
        return (await signWithEd25519Key(m!)).toRaw();
      case Key.RSA:
        return signWithRSAKey(m!).toRaw();
      default:
        throw FormatException('key type $keyType');
    }
  }

  Future<List<MapEntry<Uint8List, String>>> getRawPublicKeyList() async {
    List<MapEntry<Uint8List, String>> ret = [];
    if (ed25519 != null) {
      ret.add(MapEntry<Uint8List, String>((await getEd25519PublicKey()).toRaw(), ''));
    }
    if (ecdsaPublic != null) {
      ret.add(MapEntry<Uint8List, String>(getECDSAPublicKey().toRaw(), ''));
    }
    if (rsaPublic != null) {
      ret.add(MapEntry<Uint8List, String>(getRSAPublicKey().toRaw(), ''));
    }
    return ret;
  }
}

/// https://tools.ietf.org/html/rfc4253#section-6.6
class RSAKey with Serializable {
  String formatId = 'ssh-rsa';
  BigInt? e, n;
  RSAKey([this.e, this.n]);

  @override
  int get serializedHeaderSize => 3 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId.length + mpIntLength(e!) + mpIntLength(n!);

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    if (formatId != Key.name(Key.RSA)) throw FormatException(formatId);
    e = deserializeMpInt(input);
    n = deserializeMpInt(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeMpInt(output, e!);
    serializeMpInt(output, n!);
  }
}

/// https://tools.ietf.org/html/rfc4253#section-6.6
class RSASignature with Serializable {
  String formatId = 'ssh-rsa';
  Uint8List? sig;
  RSASignature([this.sig]);

  @override
  int get serializedHeaderSize => 4 * 2 + 7;

  @override
  int get serializedSize => serializedHeaderSize + sig!.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    sig = deserializeStringBytes(input);
    if (formatId != 'ssh-rsa') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, sig);
  }
}

/// https://tools.ietf.org/html/rfc5656#section-3.1
class ECDSAKey with Serializable {
  String? formatId, curveId;
  Uint8List? q;
  ECDSAKey([this.formatId, this.curveId, this.q]);

  @override
  int get serializedHeaderSize => 3 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId!.length + curveId!.length + q!.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    if (!formatId!.startsWith('ecdsa-sha2-')) throw FormatException(formatId!);
    curveId = deserializeString(input);
    q = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, curveId);
    serializeString(output, q);
  }
}

/// https://tools.ietf.org/html/rfc5656#section-3.1.2
class ECDSASignature with Serializable {
  String? formatId;
  BigInt? r, s;
  ECDSASignature([this.formatId, this.r, this.s]);

  @override
  int get serializedHeaderSize => 4 * 4;

  @override
  int get serializedSize =>
      serializedHeaderSize + formatId!.length + mpIntLength(r!) + mpIntLength(s!);

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    Uint8List blob = deserializeStringBytes(input);
    if (!formatId!.startsWith('ecdsa-sha2-')) throw FormatException(formatId!);
    SerializableInput blobInput = SerializableInput(blob);
    r = deserializeMpInt(blobInput);
    s = deserializeMpInt(blobInput);
    if (!blobInput.done) throw FormatException('${blobInput.offset}');
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    Uint8List blob = Uint8List(4 * 2 + mpIntLength(r!) + mpIntLength(s!));
    SerializableOutput blobOutput = SerializableOutput(blob);
    serializeMpInt(blobOutput, r!);
    serializeMpInt(blobOutput, s!);
    if (!blobOutput.done) throw FormatException('${blobOutput.offset}');
    serializeString(output, blob);
  }
}

/// https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-02#section-4
class Ed25519Key with Serializable {
  String formatId = 'ssh-ed25519';
  Uint8List? key;
  Ed25519Key([this.key]);

  @override
  int get serializedHeaderSize => 4 * 2 + 11;

  @override
  int get serializedSize => serializedHeaderSize + key!.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    key = deserializeStringBytes(input);
    if (formatId != 'ssh-ed25519') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, key);
  }
}

/// https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-02#section-6
class Ed25519Signature with Serializable {
  String formatId = 'ssh-ed25519';
  Uint8List? sig;
  Ed25519Signature([this.sig]);

  @override
  int get serializedHeaderSize => 4 * 2 + 11;

  @override
  int get serializedSize => serializedHeaderSize + sig!.length;

  @override
  void deserialize(SerializableInput input) {
    formatId = deserializeString(input);
    sig = deserializeStringBytes(input);
    if (formatId != 'ssh-ed25519') throw FormatException(formatId);
  }

  @override
  void serialize(SerializableOutput output) {
    serializeString(output, formatId);
    serializeString(output, sig);
  }
}

/// Verifies Ed25519 [signature] on [message] with private key matching [publicKey].
Future<bool> verifyEd25519Signature(
        Ed25519Key publicKey, Ed25519Signature signature, Uint8List message) async {
          final algorithm = crypto.Ed25519();
          var sign = crypto.Signature(signature.sig!, publicKey: crypto.SimplePublicKey(publicKey.key!, type: crypto.KeyPairType.ed25519));
          var ret = await algorithm.verify(message, signature: sign);
          return ret;
        } 

/// Verifies ECDSA [signature] on [message] with private key matching [publicKey].
bool verifyECDSASignature(int keyType, ECDSAKey publicKey,
    ECDSASignature signature, Uint8List message) {
  ECDSASigner signer = ECDSASigner(Key.ellipticCurveHash(keyType));
  ECDomainParameters curve = Key.ellipticCurve(keyType)!;
  signer.init(
      false,
      PublicKeyParameter(
          ECPublicKey(curve.curve.decodePoint(publicKey.q!), curve)));
  return signer.verifySignature(message, ECSignature(signature.r!, signature.s!));
}

/// Verifies RSA [signature] on [message] with private key matching [publicKey].
bool verifyRSASignature(
    RSAKey publicKey, RSASignature signature, Uint8List message) {
  RSASigner signer = RSASigner(SHA1Digest(), '06052b0e03021a');
  signer.init(
      false,
      ParametersWithRandom(
          PublicKeyParameter<asymmetric.RSAPublicKey>(
              asymmetric.RSAPublicKey(publicKey.n!, publicKey.e!)),
          NullSecureRandom()));
  return signer.verifySignature(
      message, asymmetric.RSASignature(signature.sig!));
}

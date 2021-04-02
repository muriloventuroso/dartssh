import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/sftp_content.dart';

import 'constants.dart';

/// Rounds [input] up to the next [n]th, if necessary.
int nextMultipleOfN(int input, int n) =>
    (input % n != 0) ? (input ~/ n + 1) * n : input;


/// Binary Packet Protocol. https://tools.ietf.org/html/rfc4253#section-6
abstract class SFTPMessage extends SSHMessage {
  SFTPMessage(int id) :super(id);

  Uint8List toBytes(dynamic zlib, Random random, int blockSize) {
    Uint8List payload = Uint8List(serializedSize);
    SerializableOutput output = SerializableOutput(payload);
    output.addUint32(serializedSize - 4);
    output.addUint8(id);
    serialize(output);
    if (!output.done) {
      throw FormatException('${output.offset}/${output.buffer.length}');
    }
    return payload;
  }

}

class MSG_SFTP_INIT extends SFTPMessage {
  static const int ID = 1;
  int version = 3;
  MSG_SFTP_INIT() : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 5;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    version = input.getUint32();

  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(version);
    
  }
}

class MSG_SFTP_HANDLE extends SFTPMessage {
  static const int ID = 102;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_HANDLE() : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + handle.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    
  }
}

class MSG_SFTP_VERSION extends SFTPMessage {
  static const int ID = 2;
  int version = 0;
  MSG_SFTP_VERSION() : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    version = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(version);
    
  }
}

class MSG_SFTP_NAME extends SFTPMessage {
  static const int ID = 104;
  int reqId = 0;
  int count = 0;
  List<SFTPName> names = [];
  MSG_SFTP_NAME() : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    count = input.getUint32();
    for(var i = 0; i < count; i++){
 
      var filename = deserializeString(input);
      var longname = deserializeString(input);
      var attrs = readAttrs(input);
      names.add(SFTPName(filename, longname, attrs));
    }
  }

  @override
  void serialize(SerializableOutput output) {

    
  }
}

Attrs readAttrs(SerializableInput input){
  var flags = input.getUint32();
  var attrs = Attrs();
  if(flags & ATTR_SIZE != 0){
    attrs.size = input.getUint64();
  }
  if(flags & ATTR_UIDGID != 0){
    attrs.uid = input.getUint32();
    attrs.gid = input.getUint32();
  }
  if(flags & ATTR_PERMISSIONS != 0){
    attrs.permissions = input.getUint32();
  }
  if(flags & ATTR_ACMODTIME != 0){
    attrs.atime = input.getUint32();
    attrs.mtime = input.getUint32();
  }
  if(flags & ATTR_EXTENDED != 0){
    var count = input.getUint32();
    for (var i = 0; i < count; i++){
      attrs.extensions.add(Extension(deserializeString(input), deserializeString(input)));
    }
  }
  return attrs;
}

void writeAttrs(SerializableOutput output, Attrs attrs){
  if(attrs.size != null){
    output.addUint32(ATTR_SIZE);
    output.addUint64(attrs.size);
  }
  if(attrs.uid != null && attrs.gid != null){
    output.addUint32(ATTR_UIDGID);
    output.addUint32(attrs.uid);
    output.addUint32(attrs.gid);
  }
  if(attrs.permissions != null){
    output.addUint32(ATTR_PERMISSIONS);
    output.addUint32(attrs.permissions);
  }
  if(attrs.atime != null && attrs.mtime != null){
    output.addUint32(ATTR_ACMODTIME);
    output.addUint32(attrs.atime);
    output.addUint32(attrs.mtime);
  }
  if(attrs.extensions != null){
    output.addUint32(ATTR_EXTENDED);
    output.addUint32(attrs.extensions.length);
    attrs.extensions.forEach((element) {
      serializeString(output, element.type);
      serializeString(output, element.data);
    });
  }

}

class MSG_SFTP_READDIR extends SFTPMessage {
  static const int ID = 12;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_READDIR(this.reqId, this.handle) : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + handle.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    
  }
}

class MSG_SFTP_REALPATH extends SFTPMessage {
  static const int ID = 16;
  int reqId = 0;
  String path;
  MSG_SFTP_REALPATH(this.reqId, this.path) : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {}

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
    
  }
}

class MSG_SFTP_OPENDIR extends SFTPMessage {
  static const int ID = 11;
  int reqId = 0;
  String path;
  MSG_SFTP_OPENDIR(this.reqId, this.path) : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {}

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_STATUS extends SFTPMessage {
  static const int ID = 101;
  int reqId = 0;
  int statusCode;
  String message;
  String language;
  MSG_SFTP_STATUS() : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + 8 + utf8.encode(message).length + utf8.encode(language).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    statusCode = input.getUint32();
    message = utf8.decode(deserializeStringBytes(input));
    language = utf8.decode(deserializeStringBytes(input));
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    output.addUint32(statusCode);
    serializeString(output, utf8.encode(message));
    serializeString(output, utf8.encode(language));
  }
}

class MSG_SFTP_CLOSE extends SFTPMessage {
  static const int ID = 4;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_CLOSE(this.reqId, this.handle) : super(ID);
  

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + handle.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    
  }
}

class MSG_SFTP_RENAME extends SFTPMessage {
  static const int ID = 18;
  int reqId = 0;
  String oldPath;
  String newPath;
  MSG_SFTP_RENAME(this.reqId, this.oldPath, this.newPath) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + 4 + utf8.encode(oldPath).length + utf8.encode(newPath).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    oldPath = utf8.decode(deserializeStringBytes(input));
    newPath = utf8.decode(deserializeStringBytes(input));
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, oldPath);
    serializeString(output, newPath);
  }
}

class MSG_SFTP_MKDIR extends SFTPMessage {
  static const int ID = 14;
  int reqId = 0;
  String path;
  Attrs attrs;
  MSG_SFTP_MKDIR(this.reqId, this.path, this.attrs) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 12 + utf8.encode(path).length + attrs.getSize();
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = utf8.decode(deserializeStringBytes(input));
    attrs = readAttrs(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
    writeAttrs(output, attrs);
  }
}

class MSG_SFTP_RMDIR extends SFTPMessage {
  static const int ID = 15;
  int reqId = 0;
  String path;
  
  MSG_SFTP_RMDIR(this.reqId, this.path) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = utf8.decode(deserializeStringBytes(input));
    
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_REMOVE extends SFTPMessage {
  static const int ID = 15;
  int reqId = 0;
  String filename;
  
  MSG_SFTP_REMOVE(this.reqId, this.filename) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + utf8.encode(filename).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    filename = utf8.decode(deserializeStringBytes(input));
    
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, filename);
  }
}

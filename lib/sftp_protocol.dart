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

// Requests
class MSG_SFTP_INIT extends SFTPMessage {
  static const int ID = 1;
  int version = 3;
  MSG_SFTP_INIT() : super(ID);
  MSG_SFTP_INIT.New(this.version) : super(ID);
  
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

class MSG_SFTP_VERSION extends SFTPMessage {
  static const int ID = 2;
  int version = 0;
  MSG_SFTP_VERSION() : super(ID);
  MSG_SFTP_VERSION.New(this.version) : super(ID);

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

class MSG_SFTP_OPEN extends SFTPMessage {
  static const int ID = 3;
  int reqId = 0;
  String filename;
  String mode;
  Attrs attrs;
  MSG_SFTP_OPEN() : super(ID);
  MSG_SFTP_OPEN.New(this.reqId, this.filename, this.mode, this.attrs) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + Uint8List.fromList(filename.codeUnits).length + 4 + attrs.getSize();
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    filename = utf8.decode(deserializeStringBytes(input));
    mode = flagToString(input.getUint32());
    attrs = readAttrs(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, filename);
    output.addUint32(stringFlagMap[mode]);
    writeAttrs(output, attrs);
  }
}

class MSG_SFTP_CLOSE extends SFTPMessage {
  static const int ID = 4;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_CLOSE() : super(ID);
  MSG_SFTP_CLOSE.New(this.reqId, this.handle) : super(ID);

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

class MSG_SFTP_READ extends SFTPMessage {
  static const int ID = 5;
  int reqId = 0;
  Uint8List handle;
  int offset;
  int len;
  MSG_SFTP_READ() : super(ID);
  MSG_SFTP_READ.New(this.reqId, this.handle, this.offset, this.len) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 12 + 8 + handle.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
    offset = input.getUint64();
    len = input.getUint32();
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    output.addUint64(offset);
    output.addUint32(len);
  }
}

class MSG_SFTP_WRITE extends SFTPMessage {
  static const int ID = 6;
  int reqId = 0;
  Uint8List handle;
  int offset;
  Uint8List data;
  MSG_SFTP_WRITE() : super(ID);
  MSG_SFTP_WRITE.New(this.reqId, this.handle, this.offset, this.data) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + handle.lengthInBytes + 8 + 4 + data.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
    offset = input.getUint64();
    data = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    output.addUint64(offset);
    serializeString(output, data);

  }
}

class MSG_SFTP_LSTAT extends SFTPMessage {
  static const int ID = 7;
  int reqId = 0;
  String path;
  MSG_SFTP_LSTAT() : super(ID);
  MSG_SFTP_LSTAT.New(this.reqId, this.path) : super(ID);
  
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
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_FSTAT extends SFTPMessage {
  static const int ID = 8;
  int reqId = 0;
  String path;
  MSG_SFTP_FSTAT() : super(ID);
  MSG_SFTP_FSTAT.New(this.reqId, this.path) : super(ID);
  
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
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_SETSTAT extends SFTPMessage {
  static const int ID = 9;
  int reqId = 0;
  String path;
  Attrs attrs;
  MSG_SFTP_SETSTAT() : super(ID);
  MSG_SFTP_SETSTAT.New(this.reqId, this.path, this.attrs) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + utf8.encode(path).length + attrs.getSize();
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = deserializeString(input);
    attrs = readAttrs(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
    writeAttrs(output, attrs);
  }
}

class MSG_SFTP_FSETSTAT extends SFTPMessage {
  static const int ID = 10;
  int reqId = 0;
  Uint8List handle;
  Attrs attrs;
  MSG_SFTP_FSETSTAT() : super(ID);
  MSG_SFTP_FSETSTAT.New(this.reqId, this.handle, this.attrs) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + handle.lengthInBytes + attrs.getSize();
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    handle = deserializeStringBytes(input);
    attrs = readAttrs(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, handle);
    writeAttrs(output, attrs);
  }
}

class MSG_SFTP_OPENDIR extends SFTPMessage {
  static const int ID = 11;
  int reqId = 0;
  String path;
  MSG_SFTP_OPENDIR() : super(ID);
  MSG_SFTP_OPENDIR.New(this.reqId, this.path) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_READDIR extends SFTPMessage {
  static const int ID = 12;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_READDIR() : super(ID);
  MSG_SFTP_READDIR.New(this.reqId, this.handle) : super(ID);
  
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

class MSG_SFTP_REMOVE extends SFTPMessage {
  static const int ID = 13;
  int reqId = 0;
  String filename;
  MSG_SFTP_REMOVE() : super(ID);
  MSG_SFTP_REMOVE.New(this.reqId, this.filename) : super(ID);
  
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
    filename = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, filename);
  }
}

class MSG_SFTP_MKDIR extends SFTPMessage {
  static const int ID = 14;
  int reqId = 0;
  String path;
  Attrs attrs;
  MSG_SFTP_MKDIR() : super(ID);
  MSG_SFTP_MKDIR.New(this.reqId, this.path, this.attrs) : super(ID);
  
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
  MSG_SFTP_RMDIR() : super(ID);
  MSG_SFTP_RMDIR.New(this.reqId, this.path) : super(ID);
  
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

class MSG_SFTP_REALPATH extends SFTPMessage {
  static const int ID = 16;
  int reqId = 0;
  String path;
  MSG_SFTP_REALPATH() : super(ID);
  MSG_SFTP_REALPATH.New(this.reqId, this.path) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_STAT extends SFTPMessage {
  static const int ID = 17;
  int reqId = 0;
  String path;
  MSG_SFTP_STAT() : super(ID);
  MSG_SFTP_STAT.New(this.reqId, this.path) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_RENAME extends SFTPMessage {
  static const int ID = 18;
  int reqId = 0;
  String oldPath;
  String newPath;
  MSG_SFTP_RENAME() : super(ID);
  MSG_SFTP_RENAME.New(this.reqId, this.oldPath, this.newPath) : super(ID);
  
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

class MSG_SFTP_READLINK extends SFTPMessage {
  static const int ID = 19;
  int reqId = 0;
  String path;
  MSG_SFTP_READLINK() : super(ID);
  MSG_SFTP_READLINK.New(this.reqId, this.path) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + 4 + utf8.encode(path).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    path = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, path);
  }
}

class MSG_SFTP_SYMLINK extends SFTPMessage {
  static const int ID = 20;
  int reqId = 0;
  String linkPath;
  String targetPath;
  MSG_SFTP_SYMLINK() : super(ID);
  MSG_SFTP_SYMLINK.New(this.reqId, this.linkPath, this.targetPath) : super(ID);
  
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + 4 + utf8.encode(linkPath).length + utf8.encode(targetPath).length;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    linkPath = deserializeString(input);
    targetPath = deserializeString(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, linkPath);
    serializeString(output, targetPath);
  }
}

// Responses
class MSG_SFTP_STATUS extends SFTPMessage {
  static const int ID = 101;
  int reqId = 0;
  int statusCode;
  String message;
  String language;
  MSG_SFTP_STATUS() : super(ID);
  MSG_SFTP_STATUS.New(this.reqId, this.statusCode, this.message, this.language) : super(ID);

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
    serializeString(output, message);
    serializeString(output, language);
  }
}

class MSG_SFTP_HANDLE extends SFTPMessage {
  static const int ID = 102;
  int reqId = 0;
  Uint8List handle;
  MSG_SFTP_HANDLE() : super(ID);
  MSG_SFTP_HANDLE.New(this.reqId, this.handle) : super(ID);

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

class MSG_SFTP_DATA extends SFTPMessage {
  static const int ID = 103;
  int reqId = 0;
  Uint8List data;
  MSG_SFTP_DATA() : super(ID);
  MSG_SFTP_DATA.New(this.reqId, this.data) : super(ID);

  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 8 + data.lengthInBytes;
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    data = deserializeStringBytes(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    serializeString(output, data);
  }
}

class MSG_SFTP_NAME extends SFTPMessage {
  static const int ID = 104;
  int reqId = 0;
  int count = 0;
  List<SFTPName> names = [];
  MSG_SFTP_NAME() : super(ID);
  MSG_SFTP_NAME.New(this.reqId, this.count, this.names) : super(ID);

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
 
      var filename = utf8.decode(deserializeStringBytes(input));
      var longname = utf8.decode(deserializeStringBytes(input));
      var attrs = readAttrs(input);
      names.add(SFTPName(filename, longname, attrs));
    }
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    output.addUint32(count);
    for(var i = 0; i < count; i++){
      var name = names[i];
      serializeString(output, name.filename);
      serializeString(output, name.longname);
      writeAttrs(output, name.attrs);
    }
  }
}

class MSG_SFTP_ATTRS extends SFTPMessage {
  static const int ID = 105;
  int reqId = 0;
  Attrs attrs;
  MSG_SFTP_ATTRS() : super(ID);
  MSG_SFTP_ATTRS.New(this.reqId, this.attrs) : super(ID);
  @override
  int get serializedHeaderSize => 4;

  @override
  int get serializedSize {
    int ret = serializedHeaderSize + 1 + 4 + 4 + attrs.getSize();
    return ret;
  }

  @override
  void deserialize(SerializableInput input) {
    reqId = input.getUint32();
    attrs = readAttrs(input);
  }

  @override
  void serialize(SerializableOutput output) {
    output.addUint32(reqId);
    writeAttrs(output, attrs);
  }
}

// Attrs helpers
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
  int flags = 0;
  if(attrs.size != null){
    flags |= ATTR_SIZE;
  }
  if(attrs.uid != null && attrs.gid != null){
    flags |= ATTR_UIDGID;
  }
  if(attrs.permissions != null){
    flags |= ATTR_PERMISSIONS;
  }
  if(attrs.atime != null && attrs.mtime != null){
    flags |= ATTR_ACMODTIME;
  }
  if(attrs.extensions != null && attrs.extensions.isNotEmpty){
    flags |= ATTR_EXTENDED;
  }
  output.addUint32(flags);
  if(attrs.size != null){
    output.addUint64(attrs.size);
  }
  if(attrs.uid != null && attrs.gid != null){
    output.addUint32(attrs.uid);
    output.addUint32(attrs.gid);
  }
  if(attrs.permissions != null){
    output.addUint32(attrs.permissions);
  }
  if(attrs.atime != null && attrs.mtime != null){
    output.addUint32(attrs.atime);
    output.addUint32(attrs.mtime);
  }
  if(attrs.extensions != null && attrs.extensions.isNotEmpty){
    output.addUint32(attrs.extensions.length);
    attrs.extensions.forEach((element) {
      serializeString(output, element.type);
      serializeString(output, element.data);
    });
  }

}
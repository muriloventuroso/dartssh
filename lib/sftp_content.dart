import 'constants.dart';

class SFTPName {
  String filename;
  String longname;
  Attrs attrs;

  SFTPName(this.filename, this.longname, this.attrs);

  Map toMap(){
    return {
      "filename": filename,
      "longname": longname,
      "attrs": attrs.toString()
    };
  }

  String toString(){
    return toMap().toString();
  }

  bool isDirectory() {
    return ((this.attrs.permissions & S_IFMT) == S_IFDIR);
  }
  bool isFile() {
    return ((this.attrs.permissions & S_IFMT) == S_IFREG);
  }
  bool isBlockDevice() {
    return ((this.attrs.permissions & S_IFMT) == S_IFBLK);
  }
  bool isCharacterDevice() {
    return ((this.attrs.permissions & S_IFMT) == S_IFCHR);
  }
  bool isSymbolicLink() {
    return ((this.attrs.permissions & S_IFMT) == S_IFLNK);
  }
  bool isFIFO() {
    return ((this.attrs.permissions & S_IFMT) == S_IFIFO);
  }
  bool isSocket() {
    return ((this.attrs.permissions & S_IFMT) == S_IFSOCK);
  }
  
}

class Extension {
  String type;
  String data;

  Extension(this.type, this.data);

  Map toMap(){
    return {
      "type": type,
      "data": data
    };
  }

  String toString(){
    return toMap().toString();
  }
}

class Attrs {
  int size;
  int uid;
  int gid;
  int permissions;
  int atime;
  int mtime;
  List<Extension> extensions = [];

  Map toMap(){
    return {
      "size": size,
      "uid": uid,
      "gid": gid,
      "permissions": permissions,
      "atime": atime,
      "mtime": mtime,
      "extensions": extensions.toString()
    };
  }

  String toString(){
    return toMap().toString();
  }
}
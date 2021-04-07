const ATTR_SIZE = 0x00000001;
const ATTR_UIDGID = 0x00000002;
const ATTR_PERMISSIONS = 0x00000004;
const ATTR_ACMODTIME = 0x00000008;
const ATTR_EXTENDED = 0x80000000;

const S_IFMT = 0xF000;
const S_IFDIR = 0x4000;
const S_IFSOCK = 0xC000;
const S_IFLNK = 0xA000;
const S_IFREG = 0x8000;
const S_IFBLK = 0x6000;
const S_IFCHR = 0x2000;
const S_IFIFO = 0x1000;
const S_ISUID = 0x800;
const S_ISGID = 0x400;
const S_ISVTX = 0x200;

const OPEN_MODE = {
  'READ': 0x00000001,
  'WRITE': 0x00000002,
  'APPEND': 0x00000004,
  'CREAT': 0x00000008,
  'TRUNC': 0x00000010,
  'EXCL': 0x00000020
};

Map<String, int> stringFlagMap = {
  'r': OPEN_MODE['READ'],
  'r+': OPEN_MODE['READ'] | OPEN_MODE['WRITE'],
  'w': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'],
  'wx': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'] | OPEN_MODE['EXCL'],
  'xw': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'] | OPEN_MODE['EXCL'],
  'w+': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE'],
  'wx+': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE']
         | OPEN_MODE['EXCL'],
  'xw+': OPEN_MODE['TRUNC'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE']
         | OPEN_MODE['EXCL'],
  'a': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'],
  'ax': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'] | OPEN_MODE['EXCL'],
  'xa': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['WRITE'] | OPEN_MODE['EXCL'],
  'a+': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE'],
  'ax+': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE']
         | OPEN_MODE['EXCL'],
  'xa+': OPEN_MODE['APPEND'] | OPEN_MODE['CREAT'] | OPEN_MODE['READ'] | OPEN_MODE['WRITE']
         | OPEN_MODE['EXCL']
};

String flagToString(int flag){
  stringFlagMap.forEach((key, value) {
    if(value == flag){
      return key;
    }
  });
}

const MaxPktLen = 34000 - 2 * 1024;


import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:dartssh/exceptions.dart';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/sftp_protocol.dart';
import "package:pointycastle/api.dart";
import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';
import 'package:dartssh/sftp_content.dart';
import 'package:dartssh/constants.dart';
import 'client.dart';


class SFTPClient extends SSHClient {

  String? subsystem;
  int requestId = 0;
  Map<int, Completer> _requests = {};
  VoidCallback? ftpSuccess;

  SFTPClient(
      {Uri? hostport,
      String login = '',
      bool compress = false,
      bool agentForwarding = false,
      bool? closeOnDisconnect,

      List<Forward>? forwardLocal,
      List<Forward>? forwardRemote,
      VoidCallback? disconnected,
      ResponseCallback? response,
      StringCallback? print,
      StringCallback? debugPrint,
      StringCallback? tracePrint,
      VoidCallback? success,
      this.ftpSuccess,
      FingerprintCallback? acceptHostFingerprint,
      IdentityFunction? loadIdentity,
      Uint8ListFunction? getPassword,
      SocketInterface? socketInput,
      Random? random,
      SecureRandom? secureRandom})
      : super(
            hostport: hostport,
            login: login,
            compress: compress,
            agentForwarding: agentForwarding,
            closeOnDisconnect: closeOnDisconnect,
            forwardLocal: forwardLocal,
            forwardRemote: forwardRemote,
            disconnected: disconnected,
            response: response,
            startShell: false,
            print: print,
            debugPrint: debugPrint,
            tracePrint: tracePrint,
            success: success,
            acceptHostFingerprint: acceptHostFingerprint,
            loadIdentity: loadIdentity,
            getPassword: getPassword,
            socketInput: socketInput,
            random: random,
            secureRandom: secureRandom);
  
  @override
  void handleSessionStarted() {
    super.handleSessionStarted();
    if(subsystem == null){
      sessionChannel =
        Channel(localId: nextChannelId, windowS: initialWindowSize);
      channels[nextChannelId] = sessionChannel;
      nextChannelId++;
      subsystem = "sftp";
      writeCipher(MSG_CHANNEL_OPEN(
          'session', sessionChannel!.localId, initialWindowSize, maxPacketSize));
    }else if(subsystem == "sftp"){
      writeCipher(MSG_CHANNEL_REQUEST.subsystem(sessionChannel!.remoteId, 'sftp', true));
      sendChannelData(MSG_SFTP_INIT.New(3).toBytes(null, null, null));
    }
  }

  void realPath(String path){
    sendChannelData(MSG_SFTP_REALPATH.New(requestId, path).toBytes(null, null, null));
    requestId += 1;
  }

  Future<Uint8List> openDir(String path){
    var result = Completer<Uint8List>();
    sendChannelData(MSG_SFTP_OPENDIR.New(requestId, path).toBytes(null, null, null));
    _requests[requestId] = result;
    requestId += 1;
    return result.future;
  }

  Future<List<SFTPName>> readDir(Uint8List handle){
    var result = Completer<List<SFTPName>>();
    sendChannelData(MSG_SFTP_READDIR.New(requestId, handle).toBytes(null, null, null));
    _requests[requestId] = result;
    requestId += 1;
    return result.future;
  }

  Stream<List<SFTPName>> getDirContent(String path){
    StreamController<List<SFTPName>> controller = StreamController<List<SFTPName>>();
    openDir(path).then((handle){
      completeOpenDir(handle, controller);
    });
    return controller.stream;
  }

  void completeOpenDir(Uint8List handle, StreamController<List<SFTPName>> controller){
    readDir(handle).then((files){
      if(files != null){
        controller.add(files);
      }
      completeOpenDir(handle, controller);

    }, onError: (e){
      closeHandle(handle);
      controller.close();
    });
  }

  void closeHandle(Uint8List handle){
    sendChannelData(MSG_SFTP_CLOSE.New(requestId, handle).toBytes(null, null, null));
    requestId += 1;
  }

  Future<List<SFTPName>> getRealPath(String path){
    var result = Completer<List<SFTPName>>();
    sendChannelData(MSG_SFTP_REALPATH.New(requestId, path).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<int> rename(String oldPath, String newPath){
    var result = Completer<int>();
    sendChannelData(MSG_SFTP_RENAME.New(requestId, oldPath, newPath).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<int> createDir(String path, Attrs attrs){
    var result = Completer<int>();
    sendChannelData(MSG_SFTP_MKDIR.New(requestId, path, attrs).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<int> removeDir(String path){
    var result = Completer<int>();
    sendChannelData(MSG_SFTP_RMDIR.New(requestId, path).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<int> removeFile(String filename){
    var result = Completer<int>();
    sendChannelData(MSG_SFTP_REMOVE.New(requestId, filename).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<Uint8List> openFile(String filename, String mode, Attrs attrs){
    var result = Completer<Uint8List>();
    sendChannelData(MSG_SFTP_OPEN.New(requestId, filename, mode, attrs).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<Uint8List> readFile(Uint8List handle, int offset, int len){
    var result = Completer<Uint8List>();
    sendChannelData(MSG_SFTP_READ.New(requestId, handle, offset, len).toBytes(null, null, null));
    _requests[requestId] = result;
    requestId += 1;
    return result.future;
  }

  void completeOpenFile(Uint8List handle, int offset, int len, StreamController<TransferContent> controller){
    readFile(handle, offset, len).then((data){
      if(controller.hasListener){
        var event = TransferContent(data, null, null);
        controller.add(event);
        var newOffset = offset + len;
        completeOpenFile(handle, newOffset, len, controller);
      }else{
        closeHandle(handle);
      }
    }, onError: (e){
      closeHandle(handle);
      controller.close();
    });

  }


  StreamController<TransferContent> getFileStream(String path, String mode, Attrs attrs) {
    StreamController<TransferContent> controller = StreamController<TransferContent>();
    openFile(path, mode, attrs).then((handle) {
      completeOpenFile(handle, 0, MaxPktLen, controller);
    }, onError: (e){
      controller.close();
    });
    return controller;
  }


  Future<Attrs> statPath(String path){
    var result = Completer<Attrs>();
    sendChannelData(MSG_SFTP_STAT.New(requestId, path).toBytes(null, null, null));
    _requests[requestId] = result;
    requestId += 1;
    return result.future;
  }

  Future<int?> writeFile(Uint8List handle, int offset, Uint8List data){
    var result = Completer<int?>();
    
    sendChannelData(MSG_SFTP_WRITE.New(requestId, handle, offset, data).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  Future<int> setAttrs(String path, Attrs attrs){
    var result = Completer<int>();
    sendChannelData(MSG_SFTP_SETSTAT.New(requestId, path, attrs).toBytes(null, null, null));
    _requests[requestId] = result;

    requestId += 1;
    return result.future;
  }

  /// Handles all [Channel] data for this session.
  @override
  void handleChannelData(Channel chan, Uint8List? msg) {
    if(subsystem == "sftp"){
      chan.buf.add(msg!);
      while (chan.buf.data.length > 4) {
        SerializableInput input = SerializableInput(chan.buf.data);
        int agentPacketLen = input.getUint32();
        if (input.remaining < agentPacketLen) break;
        handleSftpPacket(
            chan,
            SerializableInput(
                input.viewOffset(input.offset, input.offset + agentPacketLen)));
        chan.buf.flush(agentPacketLen + 4);
      }
    }else{
      if (chan == sessionChannel) {
        response!(this, utf8.decode(msg!));
      } else if (chan.cb != null) {
        chan.cb!(chan, msg);
      } else if (chan.agentChannel) {
        handleAgentRead(chan, msg!);
      }
    }
    
    
  }

  void handleSftpPacket(Channel channel, SerializableInput sftpPacketS){
    int sftpPacketId = sftpPacketS.getUint8();
    switch (sftpPacketId) {
      case MSG_SFTP_HANDLE.ID:
        handleMSG_SFTP_HANDLE(
            channel, MSG_SFTP_HANDLE()..deserialize(sftpPacketS));
        break;
      case MSG_SFTP_VERSION.ID:
        handleMSG_SFTP_VERSION(
            channel, MSG_SFTP_VERSION()..deserialize(sftpPacketS));
        break;
      
      case MSG_SFTP_NAME.ID:
        handleMSG_SFTP_NAME(
            channel, MSG_SFTP_NAME()..deserialize(sftpPacketS));
        break;
      
      case MSG_SFTP_DATA.ID:
        handleMSG_SFTP_DATA(
            channel, MSG_SFTP_DATA()..deserialize(sftpPacketS));
        break;
      
      case MSG_SFTP_STATUS.ID:
        handleMSG_SFTP_STATUS(
            channel, MSG_SFTP_STATUS()..deserialize(sftpPacketS));
        break;
      case MSG_SFTP_ATTRS.ID:
        handleMSG_SFTP_ATTRS(
            channel, MSG_SFTP_ATTRS()..deserialize(sftpPacketS));
        break;

      default:
        if (print != null) {
          print('$hostport: unknown sftp packet number: $sftpPacketId');
        }
        break;
    }

  }

  void handleMSG_SFTP_HANDLE(Channel channel, MSG_SFTP_HANDLE msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_HANDLE');
    }
    if(_requests.containsKey(msg.reqId)){
      if(_requests[msg.reqId] is Completer<Uint8List>){
        _requests[msg.reqId]!.complete(msg.handle);
      }
      
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_NAME(Channel channel, MSG_SFTP_NAME msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_NAME, names: ${msg.names}');
    }
    if(_requests.containsKey(msg.reqId)){
      if(_requests[msg.reqId] is Completer<List<SFTPName>>){
        Completer<List<SFTPName>> callback = _requests[msg.reqId] as Completer<List<SFTPName>>;
        callback.complete(msg.names);
      }
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_DATA(Channel channel, MSG_SFTP_DATA msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_DATA');
    }
    if(_requests.containsKey(msg.reqId)){

      if(_requests[msg.reqId] is Completer<Uint8List>){
        Completer callback = _requests[msg.reqId]!;
        callback.complete(msg.data);
      }
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_VERSION(Channel channel, MSG_SFTP_VERSION msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_VERSION version: ${msg.version}');
    }
    if(ftpSuccess != null){
      ftpSuccess!();
    }
    
  }

  void handleMSG_SFTP_STATUS(Channel channel, MSG_SFTP_STATUS msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_STATUS statusCode: ${msg.statusCode}, message: ${msg.message}');
    }
    if(_requests.containsKey(msg.reqId)){
      
      if(_requests[msg.reqId] is Completer<int> || _requests[msg.reqId] is Completer<int?>){
        Completer? callback = _requests[msg.reqId];
        if(msg.statusCode == null || msg.statusCode == 0){
          callback!.complete(msg.statusCode);
        }else{
          callback!.completeError(StatusException(msg.statusCode, msg.message));
        }
      }else if(_requests[msg.reqId] is Completer){
        Completer callback = _requests[msg.reqId]!;
        callback.completeError(StatusException(msg.statusCode, msg.message));
      }
        
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_ATTRS(Channel channel, MSG_SFTP_ATTRS msg){
    if (tracePrint != null) {
      tracePrint!('$hostport: sftp channel: MSG_SFTP_ATTRS');
    }
    if(_requests.containsKey(msg.reqId)){
      if(_requests[msg.reqId] is Completer<Attrs>){
        Completer callback = _requests[msg.reqId]!;
        callback.complete(msg.attrs);
      }
        
      _requests.remove(msg.reqId);
    }
  }

}

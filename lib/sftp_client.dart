

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:dartssh/protocol.dart';
import 'package:dartssh/serializable.dart';
import 'package:dartssh/sftp_protocol.dart';
import "package:pointycastle/api.dart";
import 'package:dartssh/socket.dart';
import 'package:dartssh/transport.dart';
import 'package:dartssh/sftp_content.dart';

import 'client.dart';

typedef HandleCallback = Function(Uint8List);
typedef NameCallback = Function(List<SFTPName>, int, String);
typedef StatusCallback = Function(int, String);

class SFTPClient extends SSHClient {

  String subsystem;
  int requestId = 0;
  Map<int, Function> _requests = {};
  VoidCallback ftpSuccess;

  SFTPClient(
      {Uri hostport,
      String login,
      bool compress = false,
      bool agentForwarding = false,
      bool closeOnDisconnect,

      List<Forward> forwardLocal,
      List<Forward> forwardRemote,
      VoidCallback disconnected,
      ResponseCallback response,
      StringCallback print,
      StringCallback debugPrint,
      StringCallback tracePrint,
      VoidCallback success,
      this.ftpSuccess,
      FingerprintCallback acceptHostFingerprint,
      IdentityFunction loadIdentity,
      Uint8ListFunction getPassword,
      SocketInterface socketInput,
      Random random,
      SecureRandom secureRandom})
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
          'session', sessionChannel.localId, initialWindowSize, maxPacketSize));
    }else if(subsystem == "sftp"){
      writeCipher(MSG_CHANNEL_REQUEST.subsystem(sessionChannel.remoteId, 'sftp', true));
      sendChannelData(MSG_SFTP_INIT().toBytes(null, null, null));
    }
  }

  void realPath(String path){
    sendChannelData(MSG_SFTP_REALPATH(requestId, path).toBytes(null, null, null));
    requestId += 1;
  }

  void openDir(String path, {HandleCallback callback}){
    sendChannelData(MSG_SFTP_OPENDIR(requestId, path).toBytes(null, null, null));
    if(callback != null){
      _requests[requestId] = callback;
    }
    requestId += 1;
    
  }

  void readDir(Uint8List handle, {NameCallback callback}){
    sendChannelData(MSG_SFTP_READDIR(requestId, handle).toBytes(null, null, null));
    if(callback != null){
      _requests[requestId] = callback;
    }
    requestId += 1;
  }

  void getFiles(String path, {NameCallback callback}){
    openDir(path, callback: (handle){
      completeOpenDir(handle, [], callback: callback);
    });
  }

  void completeOpenDir(Uint8List handle, List<SFTPName> currentNames, {NameCallback callback}){
    readDir(handle, callback: (files, error, message){
      if(files != null){
        currentNames.addAll(files);
      }
      
      if(error == null || error == 0){
        completeOpenDir(handle, currentNames, callback: callback);
      }else{
        callback(currentNames, error, message);
        closeHandle(handle);
      }
    });
  }

  void closeHandle(Uint8List handle){
    sendChannelData(MSG_SFTP_CLOSE(requestId, handle).toBytes(null, null, null));
    requestId += 1;
  }

  void getRealPath(String path, {NameCallback callback}){
    sendChannelData(MSG_SFTP_REALPATH(requestId, path).toBytes(null, null, null));
    if(callback != null){
      _requests[requestId] = callback;
    }
    requestId += 1;
  }

  /// Handles all [Channel] data for this session.
  @override
  void handleChannelData(Channel chan, Uint8List msg) {
    if(subsystem == "sftp"){
      chan.buf.add(msg);
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
        response(this, utf8.decode(msg));
      } else if (chan.cb != null) {
        chan.cb(chan, msg);
      } else if (chan.agentChannel) {
        handleAgentRead(chan, msg);
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
      
      case MSG_SFTP_STATUS.ID:
        handleMSG_SFTP_STATUS(
            channel, MSG_SFTP_STATUS()..deserialize(sftpPacketS));
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
      tracePrint('$hostport: sftp channel: MSG_SFTP_HANDLE');
    }
    if(_requests.containsKey(msg.reqId)){
      _requests[msg.reqId](msg.handle);
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_NAME(Channel channel, MSG_SFTP_NAME msg){
    if (tracePrint != null) {
      tracePrint('$hostport: sftp channel: MSG_SFTP_NAME, names: ${msg.names}');
    }
    if(_requests.containsKey(msg.reqId)){
      if(_requests[msg.reqId] is NameCallback){
        NameCallback callback = _requests[msg.reqId];
        callback(msg.names, null, null);
      }
      _requests.remove(msg.reqId);
    }
  }

  void handleMSG_SFTP_VERSION(Channel channel, MSG_SFTP_VERSION msg){
    if (tracePrint != null) {
      tracePrint('$hostport: sftp channel: MSG_SFTP_VERSION version: ${msg.version}');
    }
    if(ftpSuccess != null){
      ftpSuccess();
    }
    
  }

  void handleMSG_SFTP_STATUS(Channel channel, MSG_SFTP_STATUS msg){
    if (tracePrint != null) {
      tracePrint('$hostport: sftp channel: MSG_SFTP_STATUS statusCode: ${msg.statusCode}, message: ${msg.message}');
    }
    if(_requests.containsKey(msg.reqId)){
      
      if(_requests[msg.reqId] is NameCallback){
        NameCallback callback = _requests[msg.reqId];
        callback(null, msg.statusCode, msg.message);
      }
        
      _requests.remove(msg.reqId);
    }
  }

}

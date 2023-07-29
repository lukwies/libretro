Retro uses a binary protocol.
Each packet starts with an 8 byte header with the following
structure:

  +-+-+-+-+-+-+-+-+	V = Protocol version (2 byte)
  | V | T |   S   |	T = Packet type (2 byte)
  +-+-+-+-+-+-+-+-+	S = Packet data size (4 byte)

Packet Types:

  T_SUCCESS
  T_ERROR
  T_HELLO
  T_GOODBYE
  T_REGISTER
  T_PUBKEY
  T_GET_PUBKEY

  T_CHATMSG
  T_FILEMSG

  T_FRIENDS
  T_FRIEND_ONLINE
  T_FRIEND_OFFLINE
  T_FRIEND_UNKNOWN

  T_FILE_UPLOAD
  T_FILE_DOWNLOAD

  T_START_CALL
  T_STOP_CALL
  T_REJECT_CALL
  T_ACCEPT_CALL

## Register user ##

Before a client is able to create a retro account he/she
needs a registration key. That key can only be generated
by the retro-server and is shipped within a text file.

 Client			     Server
   |---- T_REGISTER, ---------->|  - check if regkey exists
   |	 regkey (32)		|  - generate userid
   |				|
   :				:
   |<=== T_ERROR ===============| - Invalid regkey or internal error
   |     msg (n)                |
   :				:
   |<--- T_SUCCESS -------------| - Send userid to client
   |	 userid	(8)		|
   |				|
   |---- T_PUBKEY ------------->| - Receive public key and
   |     pubkey (n)		|   store it at res/users/userid.pem
   :				:
   |<=== T_ERROR ===============|
   |     msg (n)                |
   :				:
   |<--- T_SUCCESS -------------| - Delete regkey from db and create
   :				:   entry for new user


## User Login ##

 Client			     Server
   |---- T_HELLO, ------------->| - Check if there's a public key of client
   |	 userid (8),		| - Verify signature on nonce
   |     nonce (32),		|
   |     signature (64)		|
   |				|
   |<=== T_ERROR ===============| - Unknown userid or no verify failed
   |	 message (n)		|
   |				|
   |<--- T_SUCCESS -------------| - Client logged in



# Adding a friend

For adding a friend to an account, a client needs to know the
friends id.

Client			     Server
  |				|
  |---- T_GET_PUBKEY ---------->| - check if friendId exists
  |	friendId (8)		|
  :				:
  |<=== T_ERROR ================| - friendId not found
  |	msg (n)			|
  :				:
  |<--- T_PUBKEY ---------------| - Send pubkey of friend
  |	friendId (8),		|
  |	pubkem-pem (n)		| - Inform friend!!
  :				:


## Send Chat Message ##

 Client			     Server
   |				|
   |---- T_CHATMSG, ----------->|
   |     from (8),		|
   |     to (8),		|
   |     header (256),		|
   |     signature (64),	|
   |     body (n)		|


## Ask for friends online status ##

 Client			     Server
   |				|
   |---- T_FRIENDS_STATUS, ---->|
   |     user1,user2,user3,...  |
   :				:
   |<--- T_FRIEND_ONLINE -------|
   |	 userid (8)		|
   :				:
   |<--- T_FRIEND_OFFLINE ------|
   |	 userid (8)		|
   :				:
   |<--- T_FRIEND_UNKNOWN ------|
   |	 userid (8)		|


## File upload/sending ##

 Client			    File-Server
   |				|
   |---- T_FILE_UPLOAD, ------->|
   |     fileid (16),		|
   |     filesize (4)		|
   |				|
   |<=== T_ERROR ===============|
   |     message (n)		|
   :				:
   |<--- T_SUCCESS -------------|
   |				|
   |---- <<FILE-CONTENT>> ----->|
   |     [IV+HMAC+ENCDATA]	|
   |				|
   |<=== T_ERROR ===============|
   |     message (n)		|
   :				:
   |<--- T_SUCCESS -------------|
   |				|

 Client			      Server
   |---- T_FILEMSG ------------>|
   |     from (8),		|
   |     to (8),		|
   |     header (256),		|
   |     signature (64),	|
   |     body (n) {		|
   |	  'fileid' : FILE_ID,	|
   |	  'filename' : FILENAME,|
   |	  'size' : FILE_SIZE,	|
   |	  'key' : base64(KEY)	|
   |	 }			|



# File downloading

 Client			   File-Server
   |				|
   |---- T_FILE_DOWNLOAD, ----->|
   |     fileid (16)		|
   |				|
   :				:
   |<=== T_ERROR ===============|
   |	 message (n)		|
   :				:
   |<--- T_SUCCESS -------------|
   |     filesize (4)		|
   |				|
   |<--- <<FILE CONTENT>> ------|
   |     [IV+HMAC+ENCDATA]	|



## Disconnect ##

 Client			     Server
   |				|
   |---- T_GOODBYE ------------>|






# Phone call

 Client
   |
   |
   |


###################################################################################
###################################################################################
###################################################################################

# NEW PROTOCOL


# Register
 CLIENT				     Server
   |					|
   |----- T_REGISTER ------------------>|
   |	  [regkey]			|
   |					|
   |<==== T_ERROR ======================|
   |	  [message]			|
   |					|
   |<---- T_SUCCESS --------------------|
   |	  [userid]			|
   |					|
   |----- T_REGISTER ------------------>|
   |      [rsapubkey,ecpubkey]		|
   |

# login
 CLIENT				     Server
   |					|
   |----- T_HELLO --------------------->|
   |	  [userid,nonce,signature]	|
   |					|
   |<==== T_ERROR ======================|
   |	  [message]			|
   |					|
   |<---- T_SUCCESS --------------------|
   |					|




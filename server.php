#!/php -q
<?php  /*  >php -q server.php  */

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();

class CloseConnectionException extends Exception
{ }

function Dump($data, $base = 16)
{

    if($base != 2 && $base != 16)
    {
        trigger_error("Can not dump for a base of ($base). We only support (2) and (16).");
        return false;
    }

    $i = 0;
    $length = strlen($data);
    
    if($length == 0)
        return true;

    if($base == 16)
        $colWidth = 20;
        
    else
        $colWidth = 12;

    printf('  %04d ', $i);
    
    while($i < $length)
    {
        $ascii = ord($data{$i});

        if($base == 16)
            printf(' %02X', $ascii);
    
        else
            printf(' %08b', $ascii);
    
        $i++;
        
        if($i % $colWidth == 0)
            printf("\n  %04d ", $i);
    }
    
    if($i % $colWidth > 0)
        print("\n");

    print("\nHASH: " . md5($data) . "\n\n");
        
    return true;
}
    
abstract class BaseClass
{

    protected function logInfo($message)
    {
        print(date('Y-m-d H:i:s') . ">  INFO: $message\n");
        return true;
    }
    
    protected function logError($message)
    {
        print(date('Y-m-d H:i:s') . "> ERROR: $message\n");
        return true;
    }

    protected function logWarn($message)
    {
        print(date('Y-m-d H:i:s') . ">  WARN: $message\n");
        return true;
    }

    protected function logDebug($message)
    {
        print(date('Y-m-d H:i:s') . "> DEBUG: $message\n");
        return true;
    }
}

class MessageManagement extends BaseClass
{

    const FT_CONTINUED  = 0x0;
    const FT_TEXT       = 0x1;
    const FT_BINARY     = 0x2;
    const FT_CONNCLOSE  = 0x8;
    const FT_PING       = 0x9;
    const FT_PONG       = 0xa;

    private $confReadLength = 2048,
            
            $messageCallback,
            
            $opcodeDescriptions = array(
                    self::FT_CONTINUED  => 'Continued',
                    self::FT_TEXT       => 'Text',
                    self::FT_BINARY     => 'Binary',
                    self::FT_CONNCLOSE  => 'Connection Close',
                    self::FT_PING       => 'Ping',
                    self::FT_PONG       => 'Pong',
                );

    function __construct($messageCallback)
    {
    
        if(is_callable($messageCallback) == false)
            throw new Exception("Message callback is not callable.");
    
        $this->messageCallback = $messageCallback;
    }

    function buildFrame($isFinal, $opCode, $payloadLength, $payload)
    {

        if(($opcodeDescription = $this->getOpcodeDescription($opCode)) == false)
        {
            $this->logError("Opcode of type ($opCode) is not valid. Could not send.");
            return false;
        }

        $this->logDebug("Sending ($payloadLength) bytes.  ISFINAL= [" . ($isFinal ? 'YES' : 'NO') . "]  OPCODE= [$opcodeDescription]");
    
        $buffer = '';
        
        $bitsFinal  = ($isFinal ? 1 : 0) << 7;
        $rsv        = 0x0;

        $buffer .= chr($bitsFinal | $rsv | $opCode);
        
        $masked = 0x0;
        
        if($payloadLength < 126)
            $encodedLength = chr($payloadLength);
            
        else if($payloadLength <= pow(2, 15))
            $encodedLength = chr(127) . pack('n', $payloadLength);
            
        else if($payloadLength <= pow(2, 63))
        {
            // Cut out the bytes from LSB to MSB.
            
            $i = 0;
            $payloadLengthTemp = $payloadLength;
            $bytes = array();
            while($i <= 7)
            {
                $bytes[] = $payloadLengthTemp & 0xff;
                $payloadLengthTemp >>= 8;
                
                $i++;
            }
            
            $encodedLength = chr(127) 
                                . chr($bytes[7]) . chr($bytes[6]) . chr($bytes[5]) . chr($bytes[4]) 
                                . chr($bytes[3]) . chr($bytes[2]) . chr($bytes[1]) . chr($bytes[0]);
        }
        
        $buffer .= $encodedLength;
        $buffer .= $payload;
 
Dump($buffer, 2);
 
        return $buffer;
    }

    function sendMessage($client, $opCode, $data, $frameSize = null)
    {

        if(($opcodeDescription = $this->getOpcodeDescription($opCode)) == false)
        {
            $this->logError("Opcode of type ($opCode) is not valid.");
            return false;
        }
    
        $this->logDebug("Sending message of type [$opcodeDescription] with length (" . strlen($data) . ").  FRAMESIZE= (" . ($frameSize !== null ? $frameSize : '<null>') . ")");
    
        if(($user = getuserbysocket($client)) === false)
        {
            $this->logError("Could not find user for socket for message with opcode ($opCode).");
            return false;
        }
        
        else if($user->closeSent)
        {
            $this->logError("Can not send message now that we want to close the connection.");
            return false;
        }

        if($frameSize === null)
            $frameSize = strlen($data);
        
        $i = 0;
        $messageLength = strlen($data);
        while(($i * $frameSize) < $messageLength)
        {
            $this->logDebug("Building frame ($i).");
        
            $offset = $i * $frameSize;
            $isFinal = ($offset + $frameSize) >= $messageLength;
            
            $framePayload = substr($data, $offset, $frameSize);
            
            if(($frame = $this->buildFrame($isFinal, $opCode, strlen($framePayload), $framePayload)) === false)
            {
                $this->logError("Could not build frame ($i).");
                return false;
            }

            else if(socket_write($client, $frame, strlen($frame)) === false)
            {
                $this->logError("Could not send frame ($i).");
                return false;
            }
            
            $i++;
        }

        // Return number of frames;
        return $i;
    }
    
    function processIncomingClose($client, $data)
    {
    
        if($data != '')
        {
            // If a message is given, it must be prefixed with a 16-bit reason
            // code.
            if(strlen($data) < 3)
            {
                $this->logError("A close-request was received by the payload wasn't formatted as expected.");
                return true;
            }
            
            $reasonCode = substr($data, 0, 2);
            $reasonMessage = substr($data, 2);
            
            $data = unpack('nreasonCode', $reasonCode);
            $reasonCode = $data['reasonCode'];
            
            $this->logInfo("Close request received:  CODE= ($reasonCode)  MESSAGE= [$reasonMessage]");
        }

        else
            $this->logInfo("Close request received (no reason).");

        if(($user = getuserbysocket($client)) === false)
        {
            $this->logError("Could not find user for socket with incoming close-message.");
            return false;
        }

        if($user->closeSent)
            $this->logInfo("This was an acknowledgement by the client to our close request.");
            
        else
        {
            $this->logInfo("The client is initiating a close-connection. Acknowledging.");
        
            if($this->sendClose($client) === false)
                $this->logError("Could not acknowledge client-initiated close request. Not terminating, though.");
        }

        // This was either us getting confirmation from the client that we're 
        // okay to close, or us being required by the client to close. Either 
        // way, we have to close the socket.
        
        // No more data is to be processed.
        throw new CloseConnectionException();
    }

    /**
     * Send a close-request to the client. This can either be a first-time 
     * request or an acknowledgement in response to the client.
     *
     * @return bool
     */
    function sendClose($client, $reasonCode = null, $reasonMessage = null)
    {

        if(($user = getuserbysocket($client)) === false)
        {
            $this->logError("Could not find user for socket for message with opcode ($opCode). Can not send close.");
            return false;
        }
    
        if($user->closeSent)
        {
            $this->logError("Close signal already sent.");
            return false;
        }
    
        if($reasonMessage !== null && $reasonCode === null)
        {
            $this->logError("Can not provide a message but not a reason code for a close request.");
            return false;
        }
    
        $buffer = '';
    
        if($reasonCode !== null)
            $buffer .= pack('n', $reasonCode);
        
        if($reasonMessage !== null)
            $buffer .= $reasonMessage;
    
        if($this->sendMessage($client, self::FT_CONNCLOSE, $buffer) === false)
        {
            $this->logError("Could not send close request to client.");
            return false;
        }
    
        $user->closeSent = true;

        return true;
    }

    /**
     * Extract the next message out of the byte-stream. Reads are blocking.
     *
     * @return string
     */    
    function readSocket($socket, &$buffer)
    {
    
        return @socket_recv($socket, $buffer, $this->confReadLength, 0);
    }

    function getOpcodeDescription($opCode)
    {
    
        if(isset($this->opcodeDescriptions[$opCode]) == false)
        {
            $this->logError("Opcode of type ($opCode) is not valid.");
            return false;
        }
    
        return $this->opcodeDescriptions[$opCode];
    }
    
    function messageReceived($socket, $messageInfo)
    {
    
        $opCode = $messageInfo['OpCode'];
    
        if(isset($this->opcodeDescriptions[$opCode]) == false)
        {
            $this->logError("Opcode of type ($opCode) is not valid. Skipping processing.");
            return false;
        }
    
        $opcodeDescription = $this->opcodeDescriptions[$opCode];
        
        $this->logInfo("Message of type [$opcodeDescription] received.");
        
        if($opCode == MessageManagement::FT_CONNCLOSE
                && $this->processIncomingClose(
                            $socket, 
                            $messageInfo['PayloadChain']
                        ) == false)
            $this->logError("Could not process incoming close. Not terminating.");

        else if(call_user_func(
                $this->messageCallback, 
                $this, 
                $socket, 
                $messageInfo['OpCode'], 
                $messageInfo['PayloadChain']
            ) === false)
            $this->logWarn("Message processing failed for new incoming message.");
        
        return true;
    }
}

class FrameReader extends BaseClass
{
    private $m, $socket, $buffer, $bufferSize, $ptr = 0, $counter = 0;

    /**
     * Load our state with the bytes already read, and the socket on which to 
     * keep reading.
     */
    function __construct(MessageManagement $m, $socket, $buffer)
    {
        $this->m            = $m;
        $this->socket       = $socket;
        $this->buffer       = $buffer;
        $this->bufferSize   = strlen($buffer);
    }

    /**
     * Do what's necessary to serve an N-number of bytes off the socket, using 
     * our buffering.
     *
     * @throws Exception
     * @return string
     */
    function readBytes($numBytes)
    {
    
        // Don't go anywhere until we received at least as many bytes as was 
        // requested.
        $availableBytes = ($this->bufferSize - $this->ptr + 1);
        while($availableBytes < $numBytes)
        {
            $bufferTemp = null;
            if(($length = $this->m->readSocket($this->socket, $bufferTemp)) === false)
                throw new Exception("Could not read off socket. Incoming message has faulted.");
            
            if($length == 0)
                continue;

            $this->bufferSize += $length;
            $this->buffer .= $bufferTemp;
            
            $this->logDebug("Read another ($length) bytes.");
        }
        
        $retrieved = substr($this->buffer, $this->ptr, $numBytes);
        $this->ptr += $numBytes;

        return $retrieved;
    }
    
    /**
     * After we've finished processing the frames for the next message, return 
     * all of the bytes from the front of the buffer up to the current position 
     * (non-inclusively), and remove from the buffer.
     *
     * @return string
     */
    function cutMessageFromBuffer()
    {

        $this->logDebug("Cutting complete message from front of buffer.");
    
        $removedSize = $this->ptr;
    
        $rawMessage = substr($this->buffer, 0, $this->ptr);
        $this->buffer = substr($this->buffer, $this->ptr);
        $this->bufferSize -= $removedSize;
        $this->ptr = 0;
        
        return $rawMessage;
    }
    
    /**
     * An alternative to cutMessageFromBuffer(), above, where the data isn't 
     * returned.
     *
     * @return int
     */
    function removePreviousMessage()
    {

        $this->logDebug("Removing complete message from front of buffer.");

        $removedSize = $this->ptr;
    
        $this->buffer = substr($this->buffer, $this->ptr);
        $this->bufferSize -= $removedSize;
        $this->ptr = 0;
        
        return $removedSize;
    }
    
    private function toggleMask($maskKey, $payload)
    {

        $this->logDebug("Flipping bits on (" . strlen($payload) . ") bytes.");

        $maskAscii = array(
                ord($maskKey{0}), 
                ord($maskKey{1}), 
                ord($maskKey{2}), 
                ord($maskKey{3})
            );

        $this->logDebug(sprintf("MASK: %08b %08b %08b %08b", $maskAscii[0], $maskAscii[1], $maskAscii[2], $maskAscii[3]));
            
        $i = 0;
        $flippedData = '';
        while($i < strlen($payload))
        {
            $originalByte = ord($payload{$i});
            $maskByte = $maskAscii[$i % 4];
            $resultByte = ((int)$originalByte ^ (int)$maskByte);
            
            $flippedData .= chr($resultByte);
            $i++;
        }
    
        return $flippedData;
    }

    private function readFrame()
    {

        $this->logDebug("Reading burst frame ({$this->counter}).");
    
        $firstByte  = ord($this->readBytes(1));
        $secondByte = ord($this->readBytes(1));

        $finalFlag      = ($firstByte   & 0x80) >> 7;
        $rsv            = ($firstByte   & 0x70) >> 4;
        $opCode         = ($firstByte   & 0x0F) >> 0;

        $hasMask        = ($secondByte  & 0x80) >> 7;
        $payloadLength  = ($secondByte  & 0x7F) >> 0;

        $this->logDebug(sprintf('(%05d)', $this->counter) . " ISFINAL= ($finalFlag)  RSV= ($rsv)  OPCODE= [" . dechex($opCode) . "]  HASMASK= ($hasMask)  PAYLEN= ($payloadLength)");
        
        if($payloadLength == 126)
        {
            $extendedLength = $this->readBytes(2);
            $data = unpack('nlength', $extendedLength);
            
            $actualPayloadLength = $data['length'];
        }
        
        else if($payloadLength == 127)
        {
            $extendedLength = $this->readBytes(8);
        
            // Do an unpack of a 64-bit length.

            $actualPayloadLength = 0;

//!! Convert to a loop.
//$actualPayloadLength += ord($extendedLength{$i}) << (8 - $i) * 8;
            $actualPayloadLength += ord($extendedLength{0}) << 8 * 8;
            $actualPayloadLength += ord($extendedLength{1}) << 7 * 8;
            $actualPayloadLength += ord($extendedLength{2}) << 6 * 8;
            $actualPayloadLength += ord($extendedLength{3}) << 5 * 8;
            $actualPayloadLength += ord($extendedLength{4}) << 4 * 8;
            $actualPayloadLength += ord($extendedLength{5}) << 3 * 8;
            $actualPayloadLength += ord($extendedLength{6}) << 2 * 8;
            $actualPayloadLength += ord($extendedLength{7}) << 1 * 8;
        }

        else
            $actualPayloadLength = $payloadLength;

        $this->logDebug("Actual payload length is ($actualPayloadLength). Reading payload.");
            
        $maskKey = ($hasMask == 1 ? $this->readBytes(4) : null);
        $payload = $this->readBytes($actualPayloadLength);
Dump($payload, 16);

        // We expect the client->server messages to ALWAYS have a masking key.
        if($maskKey === null)
        {
            $this->logError("Client->server payload was not masked.");
            return false;
        }

        if(($payload = $this->toggleMask($maskKey, $payload)) === false)
        {
            $this->logError("Could not unmask data.");
            return false;
        }

        return array(
                        'IsFinal'   => ($finalFlag == 1),
                        'OpCode'    => $opCode,
                        'Payload'   => $payload,
                    );
    }

    /**
     * Read and concatenate the payloads of all of the frames of the next 
     * available message. Will return NULL if the message was unparsable.
     *
     * @return string|null|false
     */
    function readIncoming()
    {

        $this->logDebug("Reading incoming messages.");
    
        $payloadChain = '';
        $opCode = null;

        try
        {
            do
            {
                $frameInfo = $this->readFrame();
                $this->counter++;

                if($frameInfo === false)
                {
                    $this->logError("Could not read frame. Breaking.");
                    return null;
                }
                
                $payloadChain .= $frameInfo['Payload'];
                
                if($opCode === null)
                    $opCode = $frameInfo['OpCode'];
                    
            } while($frameInfo['IsFinal'] == false);
        }
        
        catch(Exception $ex)
        {
            $this->logError("Could not processing incoming message because of exception [" . get_class($ex) . "]: " . $ex->getMessage());
            return false;
        }
        
        if($this->removePreviousMessage() === false)
        {
            $this->logError("Could not remove message just processed.");
            return false;
        }
        
        $messageInfo = array(
                'OpCode'        => $opCode,
                'PayloadChain'  => $payloadChain,
            );
        
        if($this->m->messageReceived($this->socket, $messageInfo) === false)
        {
            $this->logError("Message-received callback failed.");
            return false;
        }
        
        return $messageInfo;
    }
    
    /**
     * readIncoming() must be called to retrieve messages until this returns 
     * false, and then go back to a waiting/blocking state.
     *
     * @return bool
     */
    function hasMore()
    {
        return ($this->bufferSize > 0);
    }
}

function MessageProcessor(MessageManagement $m, $socket, $opCode, $data)
{

    say("[" . $m->getOpcodeDescription($opCode) . "] (" . strlen($data) . "B)> $data");


    if(($numFrames = $m->sendMessage($socket, MessageManagement::FT_TEXT, 'Received')) == false)
        trigger_error("Could not send response.");
    
    else
        say("Sent ($numFrames) frames.");
}

$m = new MessageManagement('MessageProcessor');

$master  = WebSocket('127.0.0.1', 12345);
$sockets = array($master);
$users   = array();
$debug   = true;

while(true)
{
    $changed = $sockets;
    socket_select($changed, $write = null, $except = null, null);

    foreach($changed as $socket)
    {
        if($socket==$master)
        {
            if(($client=socket_accept($master)) === false)
            { 
                console("socket_accept() failed"); 
                continue; 
            }
            else 
                connect($client);
        }
        else
        {
            $buffer = null;
            $bytes = $m->readSocket($socket, $buffer);
//!! If zero-length, the client closed the connection.
//!! This can also be false, where there was an error.
            if($bytes == 0)
                continue;

            else
            {
                $user = getuserbysocket($socket);

                if($user->handshake == false)
                    dohandshake($user,$buffer);
                else
                    try
                    {
                        process($m, $user, $buffer);
                    }
                    
                    catch(CloseConnectionException $ex)
                    {
                        $this->logInfo("Disconnecting client.");
                        
                        disconnect($socket);
                    }
            }
        }
    }
}

//---------------------------------------------------------------
function process(MessageManagement $m, $user, $initialBytes)
{

/*
logInfo("Incoming message: [$msg]");

  $action = unwrap($msg);
  say("< ".$action);
  switch($action){
    case "hello" : send($user->socket,"hello human");                       break;
    case "hi"    : send($user->socket,"zup human");                         break;
    case "name"  : send($user->socket,"my name is Multivac, silly I know"); break;
    case "age"   : send($user->socket,"I am older than time itself");       break;
    case "date"  : send($user->socket,"today is ".date("Y.m.d"));           break;
    case "time"  : send($user->socket,"server time is ".date("H:i:s"));     break;
    case "thanks": send($user->socket,"you're welcome");                    break;
    case "bye"   : send($user->socket,"bye");                               break;
    default      : send($user->socket,$action." not understood");           break;
  }*/

    print("Received (" . strlen($initialBytes) . ") initial bytes. Proceeding to processing.\n");
Dump($initialBytes, 2);
    $reader = new FrameReader($m, $user->socket, $initialBytes);
    
    while($reader->hasMore())
    {
        // Process all frames and concatenate their payloads.
        if(($messageInfo = $reader->readIncoming()) === false)
            say("Could not decode message.");
    }
}
/*
function send($client,$msg){
  say("> ".$msg);
  $msg = wrap($msg);
  socket_write($client,$msg,strlen($msg));
}
*/
function WebSocket($address,$port){
  $master=socket_create(AF_INET, SOCK_STREAM, SOL_TCP)     or die("socket_create() failed");
  socket_set_option($master, SOL_SOCKET, SO_REUSEADDR, 1)  or die("socket_option() failed");
  socket_bind($master, $address, $port)                    or die("socket_bind() failed");
  socket_listen($master,10)                                or die("socket_listen() failed");
  echo "Server Started : ".date('Y-m-d H:i:s')."\n";
  echo "Master socket  : ".$master."\n";
  echo "Listening on   : ".$address." port ".$port."\n\n";
  return $master;
}

function connect($socket){
    global $sockets,$users;
    $user = new User();
    $user->id = uniqid();
    $user->socket = $socket;
    array_push($users,$user);
    array_push($sockets,$socket);
  
    echo "Connected.\n\n";
}

function disconnect($socket){
  global $sockets,$users;
  $found=null;
  $n=count($users);
  for($i=0;$i<$n;$i++){
    if($users[$i]->socket==$socket){ $found=$i; break; }
  }
  if(!is_null($found)){ array_splice($users,$found,1); }
  $index = array_search($socket,$sockets);
  socket_close($socket);
  console($socket." DISCONNECTED!");
  if($index>=0){ array_splice($sockets,$index,1); }
}

function doNewHandshake($headers)
{

    list($resource,$host,$origin,$strkey1,$strkey2,$data,$key) = $headers;

    $gui = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    
    $upgrade =  "HTTP/1.1 101 Switching Protocols\r\n" .
                "Upgrade: websocket\r\n" .
                "Connection: Upgrade\r\n" .
                "Sec-WebSocket-Accept: " . base64_encode(sha1("$key$gui", true)) . "\r\n" . 
                "\r\n";

    return $upgrade;
}

function dohandshake($user,$buffer)
{
    print("Handshake request:\n\n" . rtrim($buffer) . "\n\n");

    list($resource,$host,$origin,$strkey1,$strkey2,$data,$key) = $headers = getheaders($buffer);

    logInfo(var_export($headers, true));

    $hash_data = $authResponse = '';
//    if($key === null)
//        $upgrade = doOldHandshake($headers);
//        
//    else
        $upgrade = doNewHandshake($headers);

    //socket_write($user->socket,$upgrade.chr(0),strlen($upgrade.chr(0)));
    socket_write($user->socket, $upgrade, strlen($upgrade));
    
    $user->handshake = true;

    print("Response:\n\n" . rtrim($upgrade) . "\n\n");

    return true;
}

function logInfo($message)
{
    error_log(date('Y-m-d H:i:s  ') . "$message\n", 3, 'log.txt');

}

function getheaders($req){
  $r=$h=$o=$key=$key1=$key2=$data=null;

  if(preg_match("/GET (.*) HTTP/"   ,$req,$match)){ $r=$match[1]; }
  if(preg_match("/Host: (.*)\r\n/"  ,$req,$match)){ $h=$match[1]; }
  if(preg_match("/Origin: (.*)\r\n/",$req,$match)){ $o=$match[1]; }
  if(preg_match("/Sec-WebSocket-Key2: (.*)\r\n/",$req,$match)){ $key2=$match[1]; }
  if(preg_match("/Sec-WebSocket-Key1: (.*)\r\n/",$req,$match)){ $key1=$match[1]; }
  if(preg_match("/Sec-WebSocket-Key: (.*)\r\n/",$req,$match)){ $key=$match[1]; }
  if(preg_match("/\r\n(.*?)\$/",$req,$match)){ $data=$match[1]; }

  return array($r,$h,$o,$key1,$key2,$data,$key);
}

function getuserbysocket($socket){
  global $users;
  $found=null;
  foreach($users as $user){
    if($user->socket==$socket){ $found=$user; break; }
  }
  return $found;
}

function     say($msg=""){ echo $msg."\n"; }
function    wrap($msg=""){ return chr(0).$msg.chr(255); }
function  unwrap($msg=""){ return substr($msg,1,strlen($msg)-2); }
function console($msg=""){ global $debug; if($debug){ echo $msg."\n"; } }

class User{
  var $id;
  var $socket;
  var $handshake;
  var $closeSent = false;
}

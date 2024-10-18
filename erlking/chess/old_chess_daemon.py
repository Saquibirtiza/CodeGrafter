import sys, daemon
import logging
from queue import Queue

from chess_integration_framework.utils.topic_definitions_file import TopicDefinitionsFile, TopicDefinitionsFileBuilder
from chess_integration_framework.connection_info import ConnectionInfo
from chess_integration_framework.topic import Topic
from chess_integration_framework.ssti import SSTI

from chess_integration_framework.proto_msg_handler import ProtoMsgHandler
import chess_messages.ar.chess_message_pb2 as chess_message

sys.path[0:0] = ['.', '..']
from mylogging.erlLogger import mylogger
import erlking

 
class MsgHandlerRequest(ProtoMsgHandler):
    def __init__(self, ss_name: str, logger, queue):
        super().__init__(chess_message.Request)
        self.ss_name = ss_name
        self.logger = logger
        self.queue = queue
     
    # Request message has to be consumed in this method
    def handle_message(self, msg_in) -> bool:
        self.logger.debug("{}: Message Received Type: {}, Source: {}, Send_Time: {}, Data: {}".
              format(self.ss_name, super().get_message_class(), msg_in.ssSource, msg_in.time, msg_in.msg))
        self.queue.put(msg_in)
        return True
 
class MsgHandlerResponse(ProtoMsgHandler):
    def __init__(self, ss_name: str, logger, queue):
        super().__init__(chess_message.Response)
        self.ss_name = ss_name
        self.logger = logger
        self.queue = queue
 
    # Response message has to be consumed in this method
    def handle_message(self, msg_in) -> bool:
        self.logger.debug("{}: Message Received Type: {}, Source: {}, Target: {}, Send_Time: {}, Data: {}".
              format(self.ss_name, super().get_message_class(), msg_in.ssSource, msg_in.ssTarget,
                     msg_in.time, msg_in.msg))
        return True

def test(ss_name,ssti):
    req_send = chess_message.Request()
    req_send.ssSource = ss_name
    req_send.time = 123
    req_send.msg = "test Request"
    ssti.send(msg_out=req_send)
    print('Sent test request')

    #res_send = chess_message.Response()
    #res_send.ssSource = ss_name
    #res_send.time = 124
    #res_send.msg = "test Response"
    #ssti.send(msg_out=res_send)
    #print('Sent test response')

def main(ss_name,topics_file):
    topic_defs = \
        TopicDefinitionsFileBuilder.parse_topics(ss_name=ss_name, \
                                                 topics_filename=topics_file)
    topic_name = 'Request_Response'
    topic = topic_defs.get_topic(topic_name=topic_name)
    conn_info = topic_defs.get_connection_info(topic_name=topic_name)

    # Create a logger, required
    log_name = 'erlking-chess'
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh = logging.FileHandler('/home/utd/logs/erlking-chess.log')
    fh.setLevel(logging.NOTSET)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    task_queue = Queue()

    rr_ssti = SSTI(topic=topic, conn_info=conn_info, log_name=log_name)

    request_handler = MsgHandlerRequest(ss_name=ss_name,logger=logger,queue=task_queue)
    response_handler = MsgHandlerResponse(ss_name=ss_name,logger=logger,queue=task_queue)

    rr_ssti.add_msg_handler(request_handler)
    rr_ssti.add_msg_handler(response_handler)

    rr_ssti.start()

    test(ss_name,rr_ssti)

    while True:
        item = task_queue.get()
        res_send = chess_message.Response()
        res_send.ssSource = ss_name
        res_send.time = 124
        res_send.msg = "Responding to '%s'"%item.msg
        rr_ssti.send(msg_out=res_send)
        logger.debug('Sent test response')
        #cmd = input('>')
        #if cmd in ['exit', 'quit', 'q']:
        #    break

    # Shutdown procedure
    rr_ssti.stop_poll()
    rr_ssti.join()
    rr_ssti.remove_msg_handler(request_handler)
    rr_ssti.remove_msg_handler(response_handler)



if __name__ == "__main__":
    if( len(sys.argv) != 3):
        print('Usage: %s <subsystem name> <topics definitions file>')
    else:
        with daemon.DaemonContext():
            main(sys.argv[1], sys.argv[2])

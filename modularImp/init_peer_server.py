import asyncio
import argparse
import logging
from socp.modularImp.server import Server
from socp.modularImp.introducerLoader import IntroducerLoader
from socp.modularImp.logging_config import setup_logging

#logging 
setup_logging() 
logger = logging.getLogger("InitPeerServer")  


logging.disable(logging.NOTSET)  
logging.getLogger("asyncio").disabled = True  
logging.getLogger("websockets").disabled = True  
logging.getLogger("websockets.client").disabled = True 
logging.getLogger("websockets.server").disabled = True 
logging.getLogger("Database").disabled = True  

async def _start_and_join(server: Server, introducer_host: str, introducer_port: int):
    async def _serve():
        await server.start()  # start server
    async def _join():
        await asyncio.sleep(0.2)  # brief delay
        ok = await server.send_server_hello_join(introducer_host, introducer_port, introducer_id="*")  # join introducer
        if not ok:
            logger.error("Failed to join introducer at %s:%s", introducer_host, introducer_port)  # join failed
    await asyncio.gather(_serve(), _join())  # run both tasks

async def run_peer_server(host: str, port: int, config_path: str, introducer_index: int):
    loader = IntroducerLoader(config_path)  # load yaml config
    introducers = loader.load()  # parse introducers
    if not introducers:
        raise RuntimeError(f"No introducers found in {config_path}")  # none found
    if not (0 <= introducer_index < len(introducers)):
        raise IndexError(f"Introducer index {introducer_index} out of range (0..{len(introducers)-1})")  # bounds check

    intro = introducers[introducer_index]  # pick introducer
    intro_host = intro["host"]  # introducer host
    intro_port = int(intro["port"])  # introducer port

    server = Server(host, port)  # create peer server
    server.is_introducer = False  # mark as peer
    logger.info("Peer server starting at %s:%s, joining introducer %s:%s", host, port, intro_host, intro_port)  # info
    await _start_and_join(server, intro_host, intro_port)  # start and join

def main():
    ap = argparse.ArgumentParser(description="Start a peer server and join an introducer from YAML")  # cli parser
    ap.add_argument("--host", default="127.0.0.1")  # server host
    ap.add_argument("--port", type=int, required=True)  # server port
    ap.add_argument("--config", default="introducers.yaml")  # config path
    ap.add_argument("--introducer-index", type=int, default=0)  # introducer index
    args = ap.parse_args()  # parse args
    asyncio.run(run_peer_server(args.host, args.port, args.config, args.introducer_index))  # run async entry

if __name__ == "__main__":
    main()  # run main

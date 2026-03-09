import asyncio
import logging
from socp.modularImp.logging_config import setup_logging
from socp.modularImp.introducerLoader import IntroducerLoader
from socp.modularImp.server import Server

#logging
setup_logging() 
logger = logging.getLogger("InitPeerServer2")

logging.getLogger("asyncio").disabled = True 
logging.getLogger("websockets").disabled = True  
logging.getLogger("websockets.client").disabled = True 
logging.getLogger("websockets.server").disabled = True 
logging.getLogger("Database").disabled = True  

#constants 
HOST = "127.0.0.1"
PORT = 26012 
CONFIG_PATH = "introducers.yaml" 
INTRODUCER_INDEX = 0

async def _start_and_join(server: Server, introducer_host: str, introducer_port: int):
    async def _serve(): # start server
        await server.start()
    async def _join(): # join introducer
        import asyncio as _aio # local alias
        await _aio.sleep(0.2) # short delay
        ok = await server.send_server_hello_join(introducer_host, introducer_port, introducer_id="*")
        if not ok: # if join fails
            logger.error("Failed to join introducer at %s:%s", introducer_host, introducer_port)
    await asyncio.gather(_serve(), _join()) # run together

async def main(): # main entry
    loader = IntroducerLoader(CONFIG_PATH) # load introducers
    intros = loader.load() # parse config
    if not intros: #none found
        raise RuntimeError(f"No introducers found in {CONFIG_PATH}")
    intro = intros[INTRODUCER_INDEX] # pick introducer
    server = Server(HOST, PORT) # create server
    server.is_introducer = False # mark as peer
    logger.info("Peer server starting at %s:%s; joining introducer %s:%s",
                HOST, PORT, intro["host"], intro["port"]) # startup info
    await _start_and_join(server, intro["host"], int(intro["port"])) # start and join

if __name__ == "__main__":
    asyncio.run(main()) # run event loop

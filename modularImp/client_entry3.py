import asyncio  # async support
import argparse  # parse command line
import logging  # logging
from socp.modularImp.client import Client  # client class
from socp.modularImp.logging_config import setup_logging  # logging setup

#logging 
setup_logging()  
logger = logging.getLogger("ClientEntry2")  

# silence the following logs
logging.getLogger("asyncio").disabled = True  
logging.getLogger("websockets").disabled = True 
logging.getLogger("websockets.client").disabled = True  
logging.getLogger("websockets.server").disabled = True 

async def main():  # program entry
    c = Client(autostart_cli=True)  # create client, autostart cli
    await c.connect("127.0.0.1", 26012)  # connect to server
    await c.wait()  # wait until client finishes

asyncio.run(main())  # run event loop
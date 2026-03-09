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
    parser = argparse.ArgumentParser(description="SOCP Client (auto interactive)")  # arg parser
    parser.add_argument("--host", default="127.0.0.1")  # host arg
    parser.add_argument("--port", type=int, default=26002)  # port arg
    args = parser.parse_args()  # parse args

    c = Client()  # make client
    await c.connect(args.host, args.port)  # connect to server
    print(f"Connected to {args.host}:{args.port}.")  # user info
    try:  # run cli
        await c.cli_loop()  # start cli loop
    finally:  # on exit
        if c.client_online:  # if connected
            await c.disconnect()  # disconnect cleanly

if __name__ == "__main__":  # run when script executed
    asyncio.run(main())  # run event loop
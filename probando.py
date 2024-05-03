from pymodbus.server.asyncio import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.client.sync import ModbusTcpClient
import asyncio

async def main_server():
    # Crear el contexto del servidor Modbus
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),  # Discrete inputs
        co=ModbusSequentialDataBlock(0, [0]*100),  # Coils
        hr=ModbusSequentialDataBlock(0, [0]*100),  # Holding registers
        ir=ModbusSequentialDataBlock(0, [0]*100)   # Input registers
    )
    context = ModbusServerContext(slaves=store, single=True)

    # Iniciar el servidor Modbus TCP en el puerto 502
    server = await StartTcpServer(context, address=("localhost", 502))

async def main_client():
    # Conectar al servidor Modbus TCP
    client = ModbusTcpClient("localhost", port=502)

    # Enviar consultas al servidor Modbus
    for i in range(5):
        # Leer un registro de entrada (input register) desde el servidor Modbus
        result = client.read_input_registers(address=0, count=1, unit=0x01)
        print(f"Respuesta del servidor Modbus: {result}")
        await asyncio.sleep(1)

async def run():
    server_task = asyncio.create_task(main_server())
    client_task = asyncio.create_task(main_client())
    await asyncio.gather(server_task, client_task)

asyncio.run(run())

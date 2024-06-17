import asyncio

from qemu.qmp import QMPClient


socket_path = "./test.sock"


async def start_record():
    try:
        qmp_client = QMPClient('test-rr')

        await qmp_client.connect(socket_path)

        with qmp_client.listener() as listener:
            res = await qmp_client.execute('rr-record')
            print(res)
        await qmp_client.disconnect()
    except Exception as e:
        print("Failed to end record {}".format(str(e)))


async def end_record():
    try:
        qmp_client = QMPClient('test-rr')

        await qmp_client.connect(socket_path)

        with qmp_client.listener() as listener:
            res = await qmp_client.execute('rr-end-record')
            print(res)
            # if res["status"] == "failed":
            #     print("end record failed: {}".format(res))
            # elif res["status"] == "completed":
            #     print("end record finished")

        await qmp_client.disconnect()
    except Exception as e:
        print("Failed to end record {}".format(str(e)))

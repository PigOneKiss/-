# !/usr/bin/env python2
# coding:utf-8
# 从Kitty中导入Template等一系列基础组件
from kitty.model import Template
from kitty.interfaces import WebInterface
from kitty.fuzzers import ServerFuzzer
from kitty.model import GraphModel
# 从Kitty扩展库katnip中导入TcpTarget用于Fuzz TCP目标
from katnip.targets.tcp import TcpTarget
# 从Kitty扩展库katnip中导入scapy模块用于直接使用Scapy的数据结构
from katnip.model.low_level.scapy import *
# 从ISF中导入modbus_tcp相关的数据包结构
from icssploit.protocols.modbus_tcp import *

def mod(ics_ip):
	print ">>>>> ICS FUZZING MODULE <<<<<\n"
	# 定义目标Fuzz对象的IP地址
	TARGET_IP = ics_ip
	# 定义目标Fuzz对象的通讯端口
	TARGET_PORT = 502
	# 定义随机数种子
	RANDSEED = int(RandShort())
	# 根据ISF中Modbus-tcp协议的数据结构构造测试数据包,下面例子中将使用RandShort对请求的地址及bit位长度进行测试
	write_coils_request_packet = ModbusHeaderRequest(func_code=0x05)/WriteSingleCoilRequest(ReferenceNumber=RandShort(), Value=RandShort())
	# 使用ScapyField直接将Scapy的数据包结构应用于Kitty框架中
	write_coils_request_packet_template = Template(name='Write Coils Request', fields=[
	    ScapyField(write_coils_request_packet,
		       name='wrire_coils_request_packet',# 定义这个Field的名字，用于在报告中显示
		       fuzzable=True,# 定义这个Field是否需要Fuzz
		       seed=RANDSEED,# 定义用于变异的随机数
		       fuzz_count=2000# 这个数据结构的fuzz次数
		       ),
	])
	# 使用GraphModel进行Fuzz
	model = GraphModel()
	# 在使用GraphModel中注册第一个节点，由于Modbus的Read Coils请求是单次的请求/回答形式，因此这里只要注册简单的一个节点即可
	model.connect(write_coils_request_packet_template)
	# 定义一个目标Target, 设置IP、端口及连接超时时间
	modbus_target = TcpTarget(name='modbus target', host=TARGET_IP, port=TARGET_PORT, timeout=2)
	# 定义是需要等待Target返回响应，如果设置为True Target不返回数据包则会被识别成异常进行记录。
	modbus_target.set_expect_response(True)
	# 定义使用ServerFuzzer的方式进行Fuzz测试
	fuzzer = ServerFuzzer()
	# 定义fuzzer使用的交互界面为web界面
	fuzzer.set_interface(WebInterface(port=26001))
	# 在fuzzer中定义使用GraphModel
	fuzzer.set_model(model)
	# 在fuzzer中定义target为modbus_target
	fuzzer.set_target(modbus_target)
	# 定义每个测试用例发送之间的延迟
	fuzzer.set_delay_between_tests(0.1)
	# 开始执行Fuzz
	fuzzer.start()

#!/usr/bin/python2
# coding:utf-8
from kitty.model import Template
from kitty.interfaces import WebInterface
from kitty.fuzzers import ServerFuzzer
from kitty.model import GraphModel
from katnip.targets.tcp import TcpTarget
from katnip.model.low_level.scapy import *
# 从ISF中导入cotp相关的数据包结构
from icssploit.protocols.cotp import *
# 从ISF中导入s7comm相关的数据包结构
from icssploit.protocols.s7comm import *

def s7(ics_ip):
	print ">>>>> ICS FUZZING MODULE <<<<<\n"

	# snap7 server 配置信息
	TARGET_IP = ics_ip
	TARGET_PORT = 102
	RANDSEED = int(RandShort())
	SRC_TSAP = "0100".encode('hex')
	DST_TSAP = "0103".encode('hex')

	# 定义COTP CR建立连接数据包
	COTP_CR_PACKET = TPKT()/COTPCR()
	COTP_CR_PACKET.Parameters = [COTPOption() for i in range(3)]
	COTP_CR_PACKET.PDUType = "CR"
	COTP_CR_PACKET.Parameters[0].ParameterCode = "tpdu-size"
	COTP_CR_PACKET.Parameters[0].Parameter = "\x0a"
	COTP_CR_PACKET.Parameters[1].ParameterCode = "src-tsap"
	COTP_CR_PACKET.Parameters[2].ParameterCode = "dst-tsap"
	COTP_CR_PACKET.Parameters[1].Parameter = SRC_TSAP
	COTP_CR_PACKET.Parameters[2].Parameter = DST_TSAP
	# 因为是建立连接使用，因此fuzzable参数需要设置为False避免数据包被变异破坏
	COTP_CR_TEMPLATE = Template(name='cotp cr template', fields=[
	    ScapyField(COTP_CR_PACKET, name='cotp cr', fuzzable=False),
	])
	# 定义通讯参数配置数据结构
	SETUP_COMM_PARAMETER_PACKET = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7SetConParameter())

	SETUP_COMM_PARAMETER_TEMPLATE = Template(name='setup comm template', fields=[
	    ScapyField(SETUP_COMM_PARAMETER_PACKET, name='setup comm', fuzzable=False),
	])
	# 定义需要Fuzzing的数据包结构, 下面例子中将使用RandShort对请求的SZLId及SZLIndex值进行变异测试
	READ_SZL_PACKET = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),Data=S7ReadSZLDataReq(SZLId=RandShort(), SZLIndex=RandShort()))
	# 定义READ_SZL_TEMPLATE为可以进行变异的结构，fuzzing的次数为1000次
	READ_SZL_TEMPLATE = Template(name='read szl template', fields=[
	    ScapyField(READ_SZL_PACKET, name='read szl', fuzzable=True, fuzz_count=1000),
	])
	# 使用GraphModel进行Fuzz
	model = GraphModel()
	# 在使用GraphModel中注册第一个节点, 首先发送COTP_CR请求。
	model.connect(COTP_CR_TEMPLATE)
	# 在使用GraphModel中注册第二个节点, 在发送完COTP_CR后发送SETUP_COMM_PARAMETER请求
	model.connect(COTP_CR_TEMPLATE, SETUP_COMM_PARAMETER_TEMPLATE)
	# 在使用GraphModel中注册第三个节点, 在发送完SETUP_COMM_PARAMETER后发送READ_SZL请求
	model.connect(SETUP_COMM_PARAMETER_TEMPLATE, READ_SZL_TEMPLATE)
	# define target
	s7comm_target = TcpTarget(name='s7comm target', host=TARGET_IP, port=TARGET_PORT, timeout=2)
	# 定义是需要等待Target返回响应，如果设置为True Target不返回数据包则会被识别成异常进行记录
	s7comm_target.set_expect_response(True)
	# 定义使用基础的ServerFuzzer进行Fuzz测试
	fuzzer = ServerFuzzer()
	# 定义fuzzer使用的交互界面为web界面
	fuzzer.set_interface(WebInterface(port=26001))
	# 在fuzzer中定义使用GraphModel
	fuzzer.set_model(model)
	# 在fuzzer中定义target为s7comm_target
	fuzzer.set_target(s7comm_target)
	# 定义每个测试用例发送之间的延迟
	fuzzer.set_delay_between_tests(0.1)
	# 开始执行Fuzz
	fuzzer.start()

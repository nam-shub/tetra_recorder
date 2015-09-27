#!/usr/bin/env python3
# coding=utf8

# A recorder for TETRA radio. Can be dropped in instead of telive.
# nam-shub <nam-shub@riseup.net>

import socket
from datetime import datetime, timedelta
from pprint import pprint, pformat
import select
import os
import sys

PORTS = [7381, 7382, 7383, 7384]
OUTPATH=os.path.join(os.getenv('HOME'), 'tetra_recordings')

class tetra_recorder:
	def __init__(self, outpath, filename_prefix, debug=False):
		self.outpath = outpath
		self.filename_prefix = filename_prefix
		self.frequency = "Unknown frequency"
		self._debug=debug

		self.channels = {}
		for channel in range(0, 64):
			self.channels[channel] = { 'file':None, 'filename':None, 'ssis':[], 'call_id':None, 'call_start':datetime.now(), 'last_payload_time':datetime.now() }
			self.update_file(channel, rename=False)

	def log(self, msg):
		print("{}: {}".format(self.frequency, msg))

	def debug(self, msg):
		if self._debug:
			print("{}: DEBUG: {}".format(self.frequency, msg))

	def update_file(self, channel, rename=False):
		filename = os.path.join(self.outpath, self.filename_prefix) + "_channel{}".format(channel)
		filename += "_" + self.channels[channel]['call_start'].isoformat()

		if self.channels[channel]['call_id']:
			filename += "_" + str(self.channels[channel]['call_id'])
			for ssi in self.channels[channel]['ssis']:
				filename += "_" + str(ssi)
		else:
			filename += "_unknown"
		filename += ".acelp"

		if rename:
			# Updating existing call with open filehandle, just rename it.
			self.log("Renaming file {} -> {}".format(self.channels[channel]['filename'], filename))
			os.rename(self.channels[channel]['filename'], filename)
		else:
			# New call
			self.log("Opening new file {}".format(filename))
			if self.channels[channel]['file']:
				self.channels[channel]['file'].close()
				if os.stat(self.channels[channel]['filename']).st_size == 0:
					os.unlink(self.channels[channel]['filename'])
			self.channels[channel]['file'] = open(filename, 'ab')

		self.channels[channel]['filename'] = filename

	def timeout_calls(self):
		for channel in self.channels:
			if self.channels[channel]['call_id']:
				now = datetime.now()
				if now - self.channels[channel]['last_payload_time'] > timedelta(minutes=5):
					self.debug("Call {} on channel {} timed out without being released.".format(self.channels[channel]['callid'], channel))
					self.channels[channel]['call_id'] = None
					self.channels[channel]['call_start'] = datetime.now()
					self.channels[channel]['last_payload_time'] = datetime.now()
					self.channels[channel]['ssis'] = []
					self.update_file(channel, rename=False)

	def disconnect_call(self, call_id, ssi):
		for chan in self.channels:
			if self.channels[chan]['call_id'] == call_id:
				try:
					self.channels[chan]['ssis'].remove(ssi)
				except ValueError:
					self.log("Attempted to remove unknown SSI {} from call_id {} channel {}".format(ssi, call_id, chan))

				if not self.channels[chan]['ssis']:
					self.log("Call ended on channel {} (call_id={}).".format(chan, self.channels[chan]['call_id']))
					self.channels[chan]['call_id'] = None
					self.channels[channel]['call_start'] = datetime.now()
					self.update_file()

				return(0)

		self.log("Attempted to disconnect SSI {} from unknown call_id {}".format(ssi, call_id))
		return(1)

	def create_call(self, call_id, channel):
		self.log("New call on channel {} (call_id={}).".format(channel, call_id))
		self.channels[channel]['call_id'] = call_id
		self.channels[channel]['call_start'] = datetime.now()
		self.channels[channel]['ssis'] = []
		self.channels[channel]['last_payload_time'] = datetime.now()
		self.update_file(channel, rename=False)

	def process_payload(self, payload_packet):
		if payload_packet[:3] == b'TRA':
			channel = int(payload_packet[3:5].decode('ascii'), 16)
			self.channels[channel]['last_payload_time'] = datetime.now()
			if(channel < 1 or channel > 63):
				#telive drops these, control channels?
				self.log("channel < 1 or channel > 63 in payload packet:\n{}".format(payload_packet))
		else:
			self.log("Payload packet with different header:\n{}".format(payload_packet))
			sys.exit(1)
		payload = payload_packet[6:]
		if not self.channels[channel]['call_id']:
			self.log("Got payload packet on channel {} but no active call there.".format(channel))
		self.debug("Received packet on channel {} (call_id={})".format(channel, self.channels[channel]['call_id']))
		self.channels[channel]['file'].write(payload)


	def process_status(self, statusmsg):
		params = statusmsg.split(' ')
		status = { 'original_message':statusmsg }

		# FIXME: This is not correct. Rewrite this to properly unpack the messages.
		# It gets the info we need for now though.
		msg = ""
		for param in params:
			try:
				option, value = param.split(':')
			except ValueError:
				msg += param + ' '
			status[option] = value
		if msg:
			status[msg] = msg

		try:
			channel = int(status['IDX'])
		except KeyError:
			channel = None

		if status['FUNC'] in ('DSETUPDEC'):
			if self.channels[channel]['call_id'] != int(status['CID']):
				self.create_call(int(status['CID']), channel)

		if status['FUNC'] in ('D-SETUP', 'D-CONNECT', 'DSETUPDEC'):
			if status['SSI'] not in self.channels[channel]['ssis']:
				self.log("New participant {} for call_id {}".format(status['SSI'], self.channels[channel]['call_id']))
				self.channels[channel]['ssis'].append(status['SSI'])
				self.update_file(channel, rename=True)

		if status['FUNC'] in ('DRELEASEDEC'):
			self.disconnect_call(int(status['CID']), status['SSI'])
				

		if status['FUNC'] in ('FREQINFO1', 'NETINFO1'):
			self.frequency = "{}MHz".format(float(status['DLF']) / (1000*1000))

		if status['FUNC'] not in ('D-SETUP', 'D-CONNECT', 'DSETUPDEC', 'D-RELEASE', 'D-DISCONNECT', 'DRELEASEDEC', 'FREQINFO1', 'NETINFO1', 'BURST', 'FREQINFO2', 'D-FACILITY', 'D-TX'):
			self.log(pformat(status))


	def read(self, s):
		data = s.recv(2048)

		if len(data) == 1386:
			self.process_payload(data)
		
		else:
			startidx = data.find(b'TETMON_begin') + 13
			endidx = data.find(b'TETMON_end') - 1
			if startidx == -1 or endidx == -1:
				self.log("Invalid message: {}".format(data))
			else:
				self.process_status(data[startidx:endidx].decode('ascii'))


def main():
	recorders = {}
	sockets = []
	for port in PORTS:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('127.0.0.1', port))
		recorders[port] = tetra_recorder(OUTPATH, "tetrarec_{}".format(port))
		sockets.append(s)


	last_timeout_run = datetime.now()
	timeout_run_interval = timedelta(seconds=30)
	while True:
		rlist, wlist, xlist = select.select(sockets, (), (), 0.1)
		for s in rlist:
			port = s.getsockname()[1]
			recorders[port].read(s)

		now = datetime.now()
		if now - last_timeout_run > timeout_run_interval:
			for recorder in recorders:
				recorders[recorder].timeout_calls()


if __name__ == '__main__':
	main()


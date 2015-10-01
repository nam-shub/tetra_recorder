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
import shutil

PORTS = [7381, 7382, 7383, 7384]
OUTPATH=os.path.join(os.getenv('HOME'), 'tetra_recordings')
FILENAME_PATTERN="{call_start}_{frequency}_{channel}_{call_id}_{ssis}.acelp"

class tetra_recorder:
	def __init__(self, outpath, filename_pattern, debug=False):
		self.outpath = outpath
		self.filename_pattern = filename_pattern
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
		ssis = [ str(ssi) for ssi in self.channels[channel]['ssis'] ]
		filename = os.path.join(
			self.outpath,
			'tmp',
			self.filename_pattern.format(
				call_start=self.channels[channel]['call_start'].isoformat(),
				frequency=self.frequency,
				channel=channel,
				call_id=self.channels[channel]['call_id'],
				ssis='_'.join(ssis)
			)
		)

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
				else:
					shutil.move(self.channels[channel]['filename'], os.path.join(self.outpath, 'acelp'))
			self.channels[channel]['file'] = open(filename, 'ab')

		self.channels[channel]['filename'] = filename

	def timeout_calls(self):
		for channel in self.channels:
			if self.channels[channel]['call_id']:
				now = datetime.now()
				if now - self.channels[channel]['last_payload_time'] > timedelta(minutes=5):
					self.debug("Call {} on channel {} timed out without being released.".format(self.channels[channel]['call_id'], channel))
					self.create_call(None, channel)

	def disconnect_call(self, call_id, ssi):
		for chan in self.channels:
			if self.channels[chan]['call_id'] == call_id:
				try:
					self.channels[chan]['ssis'].remove(ssi)
				except ValueError:
					self.log("Attempted to remove unknown SSI {} from call_id {} channel {}".format(ssi, call_id, chan))

				if not self.channels[chan]['ssis']:
					self.log("Call ended on channel {} (call_id={}).".format(chan, self.channels[chan]['call_id']))
					self.create_call(None, chan)

				return(0)

		self.log("Attempted to disconnect SSI {} from unknown call_id {}".format(ssi, call_id))
		return(1)

	def add_ssi(self, channel, ssi):
		if ssi not in self.channels[channel]['ssis']:
			self.log("New participant {} for call_id {}".format(ssi, self.channels[channel]['call_id']))
			self.channels[channel]['ssis'].append(ssi)
			self.update_file(channel, rename=True)

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

			self.add_ssi(channel, int(status['SSI']))

		if status['FUNC'] in ('D-SETUP', 'D-CONNECT'):
			if status['IDT'] == 6: # ADDR_TYPE_SSI_USAGE
				self.add_ssi(channel, int(status['SSI']))

		if status['FUNC'] in ('DRELEASEDEC'):
			self.disconnect_call(int(status['CID']), int(status['SSI']))

		if status['FUNC'] in ('NETINFO1'):
			freq = "{}MHz".format(float(status['DLF']) / (1000*1000))
			if freq != self.frequency:
				self.frequency = freq
				for channel in self.channels:
					self.update_file(channel, rename=True)

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

	try:
		os.makedirs(os.path.join(OUTPATH, 'acelp'))
		os.makedirs(os.path.join(OUTPATH, 'tmp'))
	except FileExistsError:
		pass

	for port in PORTS:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('127.0.0.1', port))
		recorders[port] = tetra_recorder(OUTPATH, FILENAME_PATTERN)
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


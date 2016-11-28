
__author__ = 'leifj'

from smartcard.scard import *
import smartcard.util

class memcard:

    def __enter__(self):
        hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_SYSTEM)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to establish context: ' + SCardGetErrorMessage(hresult))
        self.context = hcontext
        hresult, readers = SCardListReaders(hcontext, [])
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to list readers: ' + SCardGetErrorMessage(hresult))
        readers = filter(lambda r: 'ACS' in r,readers)
        self.reader = readers[0]

        hresult, hcard, dwActiveProtocol = SCardConnect(self.context,self.reader,SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
        if hresult != SCARD_S_SUCCESS:
            raise error('Unable to connect: ' + SCardGetErrorMessage(hresult))

        self.card = hcard
        self.dwActiveProtocol = dwActiveProtocol

        SELECT_CARD_TYPE = [0xFF, 0xA4, 0x00, 0x00, 0x01, 0x06]
        hresult, response = SCardTransmit(self.card, self.dwActiveProtocol, SELECT_CARD_TYPE)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to transmit: ' + SCardGetErrorMessage(hresult))

    def __exit__(self, exc_type, exc_val, exc_tb):
        hresult = SCardDisconnect(self.card, SCARD_UNPOWER_CARD)
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to disconnect: ' + SCardGetErrorMessage(hresult))
        raise exc_val

    def status(self):
        hresult, reader, state, protocol, atr = SCardStatus(self.card)
        if hresult != SCARD_S_SUCCESS:
            print('failed to get status: ' + SCardGetErrorMessage(hresult))
        return dict(reader=reader, state=hex(state), protocol=protocol, atr=smartcard.util.toHexString(atr, smartcard.util.HEX))

    def read(self, offset, length):
        READ = [0xFF, 0xB0, 0x00]
        hresult, response = SCardTransmit(self.card, self.dwActiveProtocol, READ + [offset] + [length])
        if hresult != SCARD_S_SUCCESS:
            raise error('Failed to transmit: ' + SCardGetErrorMessage(hresult))
        return response
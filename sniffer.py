
# ################################################# #
# +-----------------------------------------------+ #
# |                                               | #
# |        P r o y e c t o   S N I F F E R        | #
# |       ---------------------------------       | #
# |   Redes de Computadores - Alejandro Bergasa   | #
# |                                               | #
# +-----------------------------------------------+ #
# ################################################# #

import socket

# Método que recibe una lista en words y devuelve el checksum esperado
def CalculadoraChecksum(ListaW):
    suma = sum(ListaW)
    suma = (suma//65536) + (suma%65536)
    return 65535 - suma

# Método que recibe una lista en bytes y la devuelve en words
def BytesAWords(L8):
    L16 = []
    if len(L8)%2 != 0:
        L8.append(0)
    for i in range(0, len(L8), 2):
        L16.append(L8[i]*256 + L8[i+1])
    return L16


# -----------------------------------------------------------
# Método que desglosa el datagrama IP
# -----------------------------------------------------------
def DesgloseIP(datos):

    global i
    print('=========================================================')
    print('=========================================================')
    print(' --------- Desglose IP ---------')

    DatagramaIP = datos[0]

    # Desglosamos la cabecera

    versionIP = DatagramaIP[0] >> 4
    print('Versión: ', versionIP)

    if versionIP == 4:
        IHL = DatagramaIP[0] & 0x0F
        print('IHL: ', IHL)

        # Separamos cabecera y datos IP
        cabeceraIP = DatagramaIP[0:IHL*4]
        datosIP = DatagramaIP[IHL*4:]

        ToS = cabeceraIP[1]
        print('ToS: ', ToS)
        totalLength = cabeceraIP[2]*256 + cabeceraIP[3]
        print('Longitud total Datagrama IP: ', totalLength)
        identificador = cabeceraIP[4]*256 + cabeceraIP[5]
        print('Identificador: ', hex(identificador))
        fragmentacion = cabeceraIP[6]*256 + cabeceraIP[7]
        print('Fragmentación: ', fragmentacion)
        DF = fragmentacion & 0b0100000000000000 != 0
        print('DF: ', DF)
        MF = fragmentacion & 0b0010000000000000 != 0
        print('MF: ', MF)
        Offset = fragmentacion & 0b0001111111111111
        desplazamiento = Offset*8
        print('Offset: ', Offset)
        print('Desplazamiento: ', desplazamiento)
        TTL = cabeceraIP[8]
        print('TTL: ', TTL)
        protocolo = cabeceraIP[9]
        print('Protocolo: ', protocolo)

        # Comprobamos el checksum de la cabecera IP
        checksum = cabeceraIP[10]*256 + cabeceraIP[11]
        listaBytes = list(cabeceraIP)
        listaBytes[10] = 0
        listaBytes[11] = 0
        listaWords = BytesAWords(listaBytes)
        if(CalculadoraChecksum(listaWords) == checksum):
            comprobacion = ' (CORRECTO, calculado: ' + str(hex(CalculadoraChecksum(listaWords))) + ')'
        else:
            comprobacion = ' (INCORRECTO, calculado: ' + str(hex(CalculadoraChecksum(listaWords))) + ')'
        print('Checksum: ', hex(checksum), comprobacion)

        # Direcciones IP de origen y destino
        print('IP Origen: ', cabeceraIP[12],'.',cabeceraIP[13],'.',cabeceraIP[14],'.',cabeceraIP[15])
        print('IP Destino: ', cabeceraIP[16],'.',cabeceraIP[17],'.',cabeceraIP[18],'.',cabeceraIP[19])

        # Desglosamos un protocolo u otro en función del valor de la variable protocolo
        if(protocolo == 1):
            DesgloseICMP(datosIP)
        elif (protocolo == 6):
            DesgloseTCP(datosIP, cabeceraIP)
        elif(protocolo == 17):
            DesgloseUDP(datosIP, cabeceraIP)
        else:
            print('Datos IP = ', DatosIP)

# -----------------------------------------------------------
# Método que desglosa el segmento ICMP
# -----------------------------------------------------------
def DesgloseICMP(datos):

    global i

    print(' --------- Desglose ICMP ---------')

    # Separamos la cabecera de los datos ICMP
    CabeceraICMP=datos[0:8]
    DatosICMP=datos[8:]

    print('Cabecera ICMP: ', CabeceraICMP)

    Tipo = CabeceraICMP[0]
    print('Tipo: ', Tipo)
    Codigo = CabeceraICMP[1]

    # Comprobamos el checksum del protocolo ICMP
    checksumICMP = (CabeceraICMP[2]<<8) | (CabeceraICMP[3])
    ListaB = list(CabeceraICMP) + list(DatosICMP)
    ListaB[2] = 0
    ListaB[3] = 0
    ListaW = BytesAWords(ListaB)
    if(CalculadoraChecksum(ListaW) == checksumICMP):
        comprobacionICMP = ' (CORRECTO, calculado: ' + str(hex(CalculadoraChecksum(ListaW))) + ')'
    else:
        comprobacionICMP = ' (INCORRECTO, calculado: ' + str(hex(CalculadoraChecksum(ListaW))) + ')'
    print('Checksum: ', hex(checksumICMP), comprobacionICMP)

    # Para el tipo 0 (contestaciones de eco)
    if(Tipo==0):

        logTipo = ' (Contestacion de eco)'
        print('Tipo: ',Tipo,logTipo)

        # Distinguimos Big Endian y Little Endian
        IdBE = ((CabeceraICMP[4]<<8) | (CabeceraICMP[5]))
        IdLE = ((CabeceraICMP[5]<<8) | (CabeceraICMP[4]))
        print('Identificador (BE): ', IdBE)
        print('Identificador (LE): ', IdLE)

        # Distinguimos Big Endian y Little Endian
        secBE = ((CabeceraICMP[6]<<8) | (CabeceraICMP[7]))
        secLE = ((CabeceraICMP[7]<<8) | (CabeceraICMP[6]))
        print('Numero de secuencia (BE): ', secBE)
        print('Numero de secuencia (LE): ', secLE)


    # Para el tipo 3 (destino inalcanzable)
    elif(Tipo==3):

        logTipo = ' (Destino Inalcanzable)'
        codigo = CabeceraICMP[1]

        if(codigo == 0):
            logCodigo = ' (Red Inalcanzable)'

        elif(codigo == 1):
            logCodigo = ' (Host Inalcanzable)'

        elif(codigo == 2):
            logCodigo = ' (Protocolo Inalcanzable)'

        elif(codigo == 3):
            logCodigo = ' (Puerto Inalcanzable)'

        elif(codigo == 4):
            logCodigo = ' (Se requiere fragmentación pero bit DF activado)'

        elif(codigo == 5):
            logCodigo = ' (Ruta origen fallida)'

        elif(codigo == 6):
            logCodigo = ' (Red destino desconocida)'

        elif(codigo == 7):
            logCodigo = ' (Host destino desconocido)'

        elif(codigo == 8):
            logCodigo = ' (Host origen aislado)'

        elif(codigo == 9):
            logCodigo = ' (La comunicación con la red destino está prohibida administrativamente)'

        elif(codigo == 10):
            logCodigo = ' (La comunicación con el host destino está prohibida administrativamente)'

        elif(codigo == 11):
            logCodigo = ' (Red destino inalcanzable para el ToS)'

        elif(codigo == 12):
            logCodigo = ' (Host Destino inalcanzable para el ToS)'

        elif(codigo == 13):
            logCodigo = ' (Comunicacion prohibida administrativamente)'

        elif(codigo == 14):
            logCodigo = ' (Infracción de precedencia de host)'

        elif(codigo == 15):
            logCodigo = ' (Corte con anterioridad)'

        print('Tipo: ',Tipo,logTipo)
        print('Codigo: ',codigo,logCodigo)

    # Para el tipo 8 (peticiones de eco)
    elif(Tipo==8):

        logTipo = ' (Peticion de eco)'
        print('Tipo: ',Tipo,logTipo)

        # Distinguimos Big Endian y Little Endian
        IdBE = ((CabeceraICMP[4]<<8) | (CabeceraICMP[5]))
        IdLE = ((CabeceraICMP[5]<<8) | (CabeceraICMP[4]))
        print('Identificador (BE): ', IdBE)
        print('Identificador (LE): ', IdLE)

        # Distinguimos Big Endian y Little Endian
        secBE = ((CabeceraICMP[6]<<8) | (CabeceraICMP[7]))
        secLE = ((CabeceraICMP[7]<<8) | (CabeceraICMP[6]))
        print('Numero de secuencia (BE): ', secBE)
        print('Numero de secuencia (LE): ', secLE)

    # Para el tipo 11 (tiempo excedido)
    elif(Tipo==11):

        logTipo = ' (Tiempo excedido en datagrama)'
        codigo = CabeceraICMP[1]

        if(codigo == 0):
            logCodigo = ' (TTL excedido)'

        elif(codigo == 1):
            logCodigo = ' (Tiempo excedido en el fragmento reensamblaje)'

        print('Tipo: ',Tipo,logTipo)
        print('Codigo: ',codigo,logCodigo)

    # En caso de que el tipo de error no sea uno de los anteriores, mostramos el tipo
    else:
        print('Tipo: ',Tipo)

    print('Datos ICMP: ',DatosICMP)

    i += 1

# -----------------------------------------------------------
# Método que desglosa el segmento TCP
# -----------------------------------------------------------
def DesgloseTCP(datos, cabeceraIP):

    global i

    print(' --------- Desglose TCP ---------')

    # Separamos la cabecera UDP de los datos UDP
    CabeceraTCP = datos[0:20]
    DatosTCP = datos[20:]

    # Desglosamos los datos de la cabecera TCP
    PuertoOrigen = (CabeceraTCP[0] << 8) | (CabeceraTCP[1])
    print('Puerto origen: ',PuertoOrigen)
    PuertoDestino = (CabeceraTCP[2] << 8) | (CabeceraTCP[3])
    print('Puerto destino: ',PuertoDestino)

    NumSec = (CabeceraTCP[4] << 24) | (CabeceraTCP[5] << 16) | (CabeceraTCP[6] << 8) | (CabeceraTCP[7])
    print('Sequence number: ',NumSec)
    AckNum = (CabeceraTCP[8]<<24) | (CabeceraTCP[9]<<16) | (CabeceraTCP[10]<<8) | (CabeceraTCP[11])
    print('Acknowledgment number: ',AckNum)

    HL = ((CabeceraTCP[12]<<8)|(CabeceraTCP[13])) >> 12
    print('Longitud de la cabecera TCP: ', HL*4)

    Flags = ((CabeceraTCP[12]<<8)|(CabeceraTCP[13])) & 0x0FFF
    print('Flags: ')
    fURG = (Flags & 0b00100000) != 0
    fACK = (Flags & 0b00010000) != 0
    fPSH = (Flags & 0b00001000) != 0
    fRST = (Flags & 0b00000100) != 0
    fSYN = (Flags & 0b00000010) != 0
    fFIN = (Flags & 0b00000001) != 0
    print('    URG: ',fURG)
    print('    ACK: ',fACK)
    print('    PSH: ',fPSH)
    print('    RST: ',fRST)
    print('    SYN: ',fSYN)
    print('    FIN: ',fFIN)

    Window = (CabeceraTCP[14]<<8) | (CabeceraTCP[15])
    print('Window: ',Window)

    # Comprobamos el checksum del protocolo TCP
    checksumTCP = (CabeceraTCP[16]<<8) | (CabeceraTCP[17])
    lonTCP = len(CabeceraTCP + DatosTCP)
    ListaB = list(cabeceraIP[12:20]) + [0] + [6] + [0] + [lonTCP] + list(CabeceraTCP) + list(DatosTCP)
    ListaB[28] = 0
    ListaB[29] = 0
    ListaW = BytesAWords(ListaB)
    if(CalculadoraChecksum(ListaW) == checksumTCP):
        comprobacionTCP = ' (CORRECTO, calculado: ' + str(hex(CalculadoraChecksum(ListaW))) + ')'
    else:
        comprobacionTCP = ' (INCORRECTO, calculado: ' + str(hex(CalculadoraChecksum(ListaW))) + ')'
    print('Checksum: ', hex(checksumTCP), comprobacionTCP)

    UrgPoint = (CabeceraTCP[18]<<8) | (CabeceraTCP[19])
    print('Urgent Pointer: ',UrgPoint)

    i += 1

# -----------------------------------------------------------
# Método que desglosa el segmento UDP
# -----------------------------------------------------------
def DesgloseUDP(datos, cabeceraIP):

    global i

    print(' --------- Desglose UDP ---------')

    # Separamos la cabecera UDP de los datos UDP
    CabeceraUDP = datos[0:8]
    DatosUDP = datos[8:]

    # Desglosamos los datos de la cabecera
    PuertoOrigen = CabeceraUDP[0]*256 + CabeceraUDP[1]
    print(' Puerto Origen: ', PuertoOrigen)
    PuertoDestino = CabeceraUDP[2]*256 + CabeceraUDP[3]
    print(' Puerto Destino: ', PuertoDestino)
    LongitudUDP = CabeceraUDP[4]*256 + CabeceraUDP[5]
    print(' Longitud UDP: ', LongitudUDP)
    ChecksumUDP = CabeceraUDP[6]*256 + CabeceraUDP[7]
    print(' Checksum UDP: ', ChecksumUDP)

    # Construimos la pseudocabecera para calcular el checksum UDP
    DatosB = list(cabeceraIP[12:20]) + [0] + [17] + list(CabeceraUDP[4:6]) + list(CabeceraUDP) + list(DatosUDP)
    DatosB[18] = 0
    DatosB[19] = 0
    DatosW = BytesAWords(DatosB)
    if(CalculadoraChecksum(DatosW) == ChecksumUDP):
        comprobacionUDP = ' (CORRECTO, calculado: ' + str(hex(CalculadoraChecksum(DatosW))) + ')'
    else:
        comprobacionUDP = ' (INCORRECTO, calculado: ' + str(hex(CalculadoraChecksum(DatosW))) + ')'

    print ('Pseudocabecera UDP: ', DatosB[0:12])
    print ('Cabecera UDP: ', DatosB[12:20])
    print ('Datos UDP: ', DatosB[20:])
    print('Checksum: ', hex(ChecksumUDP), comprobacionUDP)

    if(PuertoOrigen == 53 or PuertoDestino == 53):
        DesgloseDNS(DatosUDP)
    else:
        print ('Datos UDP: ',DatosUDP)

    i += 1

# -----------------------------------------------------------
# Método que desglosa el servicio DNS
# -----------------------------------------------------------
def DesgloseDNS(datos):

    print(' --------- Desglose DNS ---------')

    # Separamos la cabecera de los datos DNS
    CabeceraDNS=datos[0:12]
    DatosDNS=datos[12:]

    # Desglosamos los datos de la cabecera DNS
    Id = (CabeceraDNS[0]<<8) | (CabeceraDNS[1])
    print('ID: ', hex(Id))
    Flags = (CabeceraDNS[2]<<8) | (CabeceraDNS[3])
    print('Flags: ', hex(Flags))
    NConsultas = (CabeceraDNS[4]<<8) | (CabeceraDNS[5])
    NResp = (CabeceraDNS[6]<<8) | (CabeceraDNS[7])
    NAuto = (CabeceraDNS[8]<<8) | (CabeceraDNS[9])
    NAdic = (CabeceraDNS[10]<<8) | (CabeceraDNS[11])

    if((NResp > 0 or NAuto>0) or NAdic>0):
        print('Mensaje de respuesta')
    else:
        print('Mensaje de consulta')

    print('Consultas: ', NConsultas)
    print('Registros de recursos de respuestas: ', NResp)
    print('Tegistros de recursos de servidores autorizados: ', NAuto)
    print('Registros de recursos adicionales: ', NAdic)

    x = False
    k = 0
    pag = ''

    while(not x):
        if(DatosDNS[k] == 0):
            x = True
        elif(k != 0 and DatosDNS[k] < 27):
            pag += '.'
        elif(k != 0):
            pag += chr(DatosDNS[k])
        k += 1

    print('Consulta: ')
    print('  - Pagina: ', pag)
    tipoC = (DatosDNS[k] << 8) | (DatosDNS[k+1])

    if(tipoC == 1):
        print('  - Tipo: ', tipoC, ' (A)')
    elif(tipoC == 2):
        print('  - Tipo: ', tipoC, '(NS)')
    elif(tipoC == 5):
        print('  - Tipo: ', tipoC, '(CNAME)')
    elif(tipoC == 12):
        print('  - Tipo: ', tipoC, '(PTR)')
    elif(tipoC == 15):
        print('  - Tipo: ', tipoC, '(MX)')
    elif(tipoC == 28):
        print('  - Tipo: ', tipoC, '(AAAA)')
    else:
        print('  - Tipo: ', tipoC)

    claseC = (DatosDNS[k+2] << 8) | (DatosDNS[k+3])
    print('  - Clase: ', hex(claseC))

    iterador = 0
    msgDNS = DatosDNS[k+4:]

    if(NResp > 0):
        for w in range(NResp):
            print('Respuesta numero ', w+1, ':')
            nombreR = (msgDNS[iterador] << 8) | (msgDNS[iterador + 1])
            print('  - Nombre: ', hex(nombreR))
            tipoR = (msgDNS[iterador + 2] << 8) | (msgDNS[iterador + 3])
            DN = ''

            if(tipoR == 1):
                print('  - Tipo: ', tipoR, '(A)')
                DN = 'Address'
            elif(tipoR == 2):
                print('  - Tipo: ', tipoR, '(NS)')
                DN = 'NS'
            elif(tipoR == 5):
                print('  - Tipo: ', tipoR, '(CNAME)')
                DN = 'CNAME'
            elif(tipoR == 12):
                print('  - Tipo: ', tipoR, '(PTR)')
                DN = 'PTR'
            elif(tipoR == 15):
                print('  - Tipo: ', tipoR, '(MX)')
                DN = 'MX'
            elif(tipoR == 28):
                print('  - Tipo: ', tipoR, '(AAAA)')
                DN = 'AAAA'
            else:
                print('  - Tipo: ', tipoR)
                DN = 'Data'

            claseR = (msgDNS[iterador + 4] << 8) | (msgDNS[iterador + 5])
            print('  - Clase: ', hex(claseR))

            TTL = (msgDNS[iterador + 6] << 24) | (msgDNS[iterador + 7] << 16) | (msgDNS[iterador + 8] << 8) | (msgDNS[iterador + 9])
            print('  - TTL: ', TTL)

            longDatos = (msgDNS[iterador + 10] << 8) | (msgDNS[iterador + 11])
            print('  - Longitud de los datos: ', longDatos)

            iterador += 12
            string = ''

            if(tipoR == 1):
                for t in range(longDatos):
                    if(t == 0):
                        string += ascii(msgDNS[iterador])
                    elif(t != 0):
                        string += '.' + ascii(msgDNS[iterador])
                    iterador += 1
            elif(tipoR == 2 or tipoR == 5):
                for t in range(longDatos):
                    if(msgDNS[iterador] == 0):
                        string += ' '
                    elif(msgDNS[iterador] < 27 and t != 0 and msgDNS[iterador] != 0):
                        string += '.'
                    elif(t != 0):
                        string += chr(msgDNS[iterador])
                    iterador += 1
            else:
                for t in range(longDatos):
                    string += ascii(msgDNS[iterador])
                    iterador += 1

            print(DN, ': ', string)

    if(NAdic > 0):
        for w in range(NAdic):
            print('Registro de recursos de servidores autorizados ', w+1, ': ')

            nombreA = (msgDNS[iterador] << 8) | (msgDNS[iterador + 1])
            print('  - Nombre: ', hex(nombreA))
            tipoA = (msgDNS[iterador + 2] << 8) | (msgDNS[iterador + 3])
            DN = ''

            if(tipoA == 1):
                print('  - Tipo: ', tipoR, '(A)')
                DN = 'Address'
            elif(tipoA == 2):
                print('  - Tipo: ', tipoR, '(NS)')
                DN = 'NS'
            elif(tipoA == 5):
                print('  - Tipo: ', tipoR, '(CNAME)')
                DN = 'CNAME'
            elif(tipoA == 12):
                print('  - Tipo: ', tipoR, '(PTR)')
                DN = 'PTR'
            elif(tipoA == 15):
                print('  - Tipo: ', tipoR, '(MX)')
                DN = 'MX'
            elif(tipoA == 28):
                print('  - Tipo: ', tipoR, '(AAAA)')
                DN = 'AAAA'
            else:
                print('  - Tipo: ', tipoR)
                DN = 'Data'

            claseA = (msgDNS[iterador + 4] << 8) | (msgDNS[iterador + 5])
            print('  - Clase: ', hex(classA))

            TTL = (msgDNS[iterador + 6] << 24) | (msgDNS[iterador + 7] << 16) | (msgDNS[iterador + 8] << 8) | (msgDNS[iterador + 9])
            print('  - TTL: ', TTL)

            long = (msgDNS[iterador + 10] << 8) | (msgDNS[iterador + 11])
            print('  - Longitud: ', long)

            iterador += 12
            string = ''

            if(tipoA == 1):
                for t in range(long):
                    if(t == 0):
                        string += ascii(msgDNS[iterador])
                    elif(t != 0):
                        string += '.' + ascii(msgDNS[iterador])
                    iterador += 1
            elif(tipoA == 2 or tipoA == 5):
                for t in range(long):
                    if(msgDNS[iterador] == 0):
                        string += ' '
                    elif(msgDNS[iterador] < 27 and t != 0 and msgDNS[iterador] != 0):
                        string += '.'
                    elif(t != 0):
                        string += chr(msgDNS[iterador])
                    iterador += 1
            else:
                for t in range(long):
                    string += ascii(msgDNS[iterador])
                    iterador += 1

            print(DN, ': ', string)


# Captura del paquete

HOST = "192.168.1.138"

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# La siguiente línea capturaría un paquete
# datos = s.recvfrom(65565)

##i = 0
##while(i < 10):
##    CapturaDatagramaUDP()

# print(s.recvfrom(65565))

# mensaje = s.recvfrom(65565)
# DatagramaIP = mensaje[0]


i = 0

for i in range(10):
    datos = s.recvfrom(65565)
    print('---------------------------------------------------------------------------')
    print('    Captura número ',i+1)
    print('---------------------------------------------------------------------------')
    DesgloseIP(datos)


##j = 20
##while(j>0):
##    datos = s.recvfrom(65565)
##    if(datos[0][9] == 6):
##        DesgloseIP(datos)
##        j = j - 1


s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
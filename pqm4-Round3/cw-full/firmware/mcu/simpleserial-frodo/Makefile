TARGET = simpleserial-frodo
PQMROOT  = /Users/vicentiastroe/Documents/Thesis/FrodoKEM/pqm4-Round3
FRODODIR = $(PQMROOT)/crypto_kem/frodokem640shake/m4
FIPSDIR  = $(PQMROOT)/mupq/common
RNGDIR   = $(PQMROOT)/common
CWHAL    = $(PQMROOT)/cw-full/firmware/mcu/hal   
OPENCM3  = $(PQMROOT)/libopencm3/include

VPATH += $(FRODODIR)
VPATH += $(FIPSDIR)
VPATH += $(RNGDIR)

SRC += simpleserial-frodo.c
SRC += hal_stub.c
SRC += kem.c
SRC += noise.c
SRC += util.c
SRC += matrix_shake.c
SRC += fips202.c
SRC += randombytes.c

ASRC += frodo_kem.S
ASRC += frodo_shake_kem.S
ASRC += keccakf1600.S

EXTRAINCDIRS += .
EXTRAINCDIRS += $(CWHAL)         
EXTRAINCDIRS += $(CWHAL)/chipwhisperer-fw-extra/stm32f4 
EXTRAINCDIRS += $(FRODODIR)
EXTRAINCDIRS += $(FIPSDIR)
EXTRAINCDIRS += $(RNGDIR)
EXTRAINCDIRS += $(OPENCM3)

CFLAGS += -include trigger.h

ifeq ($(CRYPTO_TARGET),)
CRYPTO_TARGET = NONE
endif

${info Building for platform ${PLATFORM} with CRYPTO_TARGET=$(CRYPTO_TARGET)}
include ../simpleserial/Makefile.simpleserial
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
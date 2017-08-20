ocra
======
Golang OATH OCRA implementation. 

## Status
[![Build Status](https://travis-ci.org/nexocrew/ocra.svg?branch=master)](https://travis-ci.org/nexocrew/ocra)
[![GoDoc](https://godoc.org/github.com/nexocrew/ocra?status.svg)](https://godoc.org/github.com/nexocrew/ocra)
[![GitHub issues](https://img.shields.io/github/issues/nexocrew/ocra.svg "GitHub issues")](https://github.com/nexocrew/ocra)

Table of contents
---------------------

 - [Context](#context)
 - [Description](#description)
 - [Installation](#installation)
 - [Contribution](#contribution)
 - [Contributors](#contributors)

 ## Context

OCRA is an algorithm for challenge-response authentication developed by the Initiative for Open Authentication (OATH).  The specified mechanisms leverage the HMAC-based One-Time Password (HOTP) algorithm and offer one-way and mutual authentication, and electronic signature capabilities.

The Initiative for Open Authentication (OATH) [OATH] has identified several use cases and scenarios that require an asynchronous variant to accommodate users who do not want to maintain a synchronized authentication system.  A commonly accepted method for this is to use a challenge-response scheme.

Such a challenge-response mode of authentication is widely adopted in the industry.  Several vendors already offer software applications and hardware devices implementing challenge-response -- but each of those uses vendor-specific proprietary algorithms. For the benefits of users there is a need for a standardized challenge-response algorithm that allows multi-sourcing of token purchases and validation systems to facilitate the democratization of strong authentication.

Additionally, this specification describes the means to create symmetric key-based short 'electronic signatures'.  Such signatures are variants of challenge-response mode where the data to be signed becomes the challenge or is used to derive the challenge.  Note that the term 'electronic signature' and 'signature' are used interchangeably in this document.

See complete [RFC6287 documentation](https://tools.ietf.org/html/rfc6287)

 ## Description

 This is a native Golang implementation of the RFC6287 document.

 ## Installation

 To install the package symply run ```go install``` from the terminal (requires a correctly set GOPATH).

 ## Contribution

The project is in the early development stages: contributors are welcome! Please before contributing read the [issues](https://github.com/nexocrew/ocra/issues).
Thanks!

## Contributors
[@dyst0ni3](https://github.com/dystonie)
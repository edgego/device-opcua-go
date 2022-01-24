# Copyright (c) 2020-2021 EdgeGO
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG BASE=golang:1.16-alpine3.14
FROM ${BASE} AS builder
ENV GOPROXY=https://goproxy.cn

RUN sed -e 's/dl-cdn[.]alpinelinux.org/nl.alpinelinux.org/g' -i~ /etc/apk/repositories
RUN apk add --update --no-cache make git openssh gcc libc-dev zeromq-dev libsodium-dev

# set the working directory
WORKDIR /device-opcua-go

COPY . .

RUN go mod tidy
RUN [ ! -d "vendor" ] && go mod download all

RUN wget https://github.com.cnpmjs.org/edgego/device-sdk-go/archive/refs/tags/v2.1.0-prom.zip
RUN unzip v2.1.0-prom.zip
RUN cd device-sdk-go-2.1.0-prom && tar xf device-sdk-go.tar.gz && rm -rf $GOPATH/pkg/mod/github.com/edgexfoundry/device-sdk-go/v2@v2.1.0
RUN  mv ./device-sdk-go-2.1.0-prom/device-sdk-go/ $GOPATH/pkg/mod/github.com/edgexfoundry/device-sdk-go/v2@v2.1.0/ && rm v2.1.0-prom.zip
RUN make build

FROM alpine:3.14

LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) 2019-2021: EdgeGo Ltd'

RUN sed -e 's/dl-cdn[.]alpinelinux.org/nl.alpinelinux.org/g' -i~ /etc/apk/repositories
RUN apk add --update --no-cache zeromq dumb-init

COPY --from=builder /device-opcua-go/cmd /
COPY --from=builder /device-opcua-go/LICENSE /
COPY --from=builder /device-opcua-go/Attribution.txt /

EXPOSE 59989

ENTRYPOINT ["/device-opcua"]
CMD ["--cp=consul://edgex-core-consul:8500", "--registry", "--confdir=/res"]

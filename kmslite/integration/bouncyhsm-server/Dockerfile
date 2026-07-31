# syntax=docker/dockerfile:1
# BouncyHsm server image — built from the official release ZIP.
# Runs on any Docker host (macOS Apple Silicon uses arm64 aspnet:10.0
# natively; no emulation needed).
#
# Version bump: change BOUNCYHSM_VERSION and rebuild.

FROM alpine:3.23 AS unzip
ARG BOUNCYHSM_VERSION=2.3.0
WORKDIR /unzip
ADD https://github.com/harrison314/BouncyHsm/releases/download/v${BOUNCYHSM_VERSION}/BouncyHsm.zip .
RUN apk add --no-cache unzip && unzip BouncyHsm.zip && rm BouncyHsm.zip

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /App
COPY --from=unzip /unzip /App

EXPOSE 8080 8765
VOLUME /var/BouncyHsm/
ENV ASPNETCORE_ENVIRONMENT=Docker

CMD ["dotnet", "BouncyHsm.dll"]

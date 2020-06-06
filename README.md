# Prometheus Exporter Toolkit

[![CircleCI](https://circleci.com/gh/prometheus/exporter-toolkit/tree/master.svg?style=shield)][circleci]
[![Go Report Card](https://goreportcard.com/badge/github.com/prometheus/exporter-toolkit)][goreportcard]
[![go-doc](https://godoc.org/github.com/prometheus/exporter-toolkit?status.svg)][godoc]

This is a [Go](http://golang.org) library for [Prometheus](http://prometheus.io)
[exporters][exporter].

This repository is meant to be used in combination with the
[client_golang][client_golang] repository. If you are
[instrumenting][instrumentation] an existing Go application,
[client_golang][client_golang] is the repository you are looking for.

**This repository is currently WIP and experimental.**

[circleci]:https://circleci.com/gh/prometheus/exporter-toolkit
[client_golang]:https://github.com/prometheus/client_golang
[exporter]:https://prometheus.io/docs/introduction/glossary/#exporter
[godoc]:https://godoc.org/github.com/prometheus/exporter-toolkit
[goreportcard]:https://goreportcard.com/report/github.com/prometheus/exporter-toolkit
[instrumentation]:https://prometheus.io/docs/introduction/glossary/#direct-instrumentation

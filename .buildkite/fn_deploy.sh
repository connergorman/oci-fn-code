#!/usr/bin/bash

fn use context $(buildkite-agent meta-data get context)
fn build $(buildkite-agent meta-data get directory)
fn push

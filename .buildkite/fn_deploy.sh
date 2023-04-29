#!/usr/bin/bash

fn use context $(buildkite-agent meta-data get context)
cd $(buildkite-agent meta-data get directory)
fn build 
fn push

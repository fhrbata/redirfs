#!/bin/bash
low="../low"
high="../high"
deep=100

rm -rf $high
rm -rf $low

string=$low

mkdir $string
for i in `seq 1 $deep`;
do
	string+="/dir$i"
	mkdir $string
done

touch $string/searched 

string=$high

mkdir $string
for i in `seq 1 $deep`;
do
	string+="/dir$i"
	mkdir $string
done







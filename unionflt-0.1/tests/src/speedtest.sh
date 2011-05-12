#!/bin/bash
low="low"
high="high"
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


########################
# Test

# time find $union > /dev/null = provereni lookupu
# time cat $soubor_v_hloubce > /dev/null = lookup


rm -rf $low
rm -rf $high

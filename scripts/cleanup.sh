#!/bin/bash
find ./agent_reports -name "raw_*.log" -mmin +60 -delete 2>/dev/null
find ./agent_reports -name "raw_*.log" -size +10M -delete 2>/dev/null
du -sh ./agent_reports/
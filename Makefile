# Do not modify the Makefile

-include conf/lab.mk
-include conf/info.mk


esh: esh.c
	gcc esh.c -o esh

clean:
	rm -f *.o esh


STYLE=\033[1;31m
NC=\033[0m
URL=http://114.212.81.7:9999

info-check:
	@if test -z "$(SID)"; then \
		echo "${STYLE}Please set SID in conf/info.mk${NC}"; \
		false; \
	fi
	@if test -z "`echo $(SID) | grep '^[0-9]\{9\}$$'`"; then \
		echo -n "${STYLE}Your SID (${SID}) does not appear to be correct. Continue? [y/N]${NC} "; \
		read -p "" r; \
		test "$$r" = y; \
	fi
	@if test -z "$(TOKEN)"; then \
		echo "${STYLE}Please set TOKEN in conf/info.mk${NC}"; \
		false; \
	fi

submit: info-check
	curl -F "token=${TOKEN}" -F "lab_num=${LAB_NUM}" -F "file=@esh.c" ${URL}/upload_code

report: info-check
	@if ! test -f $(SID).pdf; then \
		echo "${STYLE}Please put your report in a file named $(SID).pdf${NC}"; \
		false; \
	fi
	curl -F "token=${TOKEN}" -F "lab_num=${LAB_NUM}" -F "file=@${SID}.pdf" ${URL}/upload_report

score: info-check
	curl "${URL}/download?token=${TOKEN}&lab_num=${LAB_NUM}"

.PHONY: clean info-check submit report score

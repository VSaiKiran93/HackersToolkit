from rest_framework import serializers

class NmapScanSerializer(serializers.Serializer):
    ip_address = serializers.CharField(max_length=255)
    port_range = serializers.CharField(max_length=255)
    scan_type = serializers.ChoiceField(choices=[('sS', 'Syn Stealth Scan'), ('sT', 'TCP Connect Scan'), ('sU', 'UDP Scan'), ('A', 'Aggresive Scan')])

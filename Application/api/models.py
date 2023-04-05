from django.db import models

class Scan(models.Model):
    ip_address = models.CharField(max_length=100)
    report = models.TextField() 
    created_at = models.DateTimeField(auto_now_add = True)
    
    def __str__(self):
        return self.ip_address


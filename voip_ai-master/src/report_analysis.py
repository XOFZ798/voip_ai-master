class Analysis:
    def __init__(self, text):
        self.text = text
        self.defrost = False
        self.lines = self.extract_relevant_lines()

    def extract_relevant_lines(self):
        """فقط خطوطی که با Vbat=، HUM1=، TEMP1=، Credit=، relays= و inputs= شروع می‌شوند را نگه می‌دارد."""
        valid_keys = ("Vbat=", "HUM1=", "TEMP1=", "Credit=", "relays=", "inputs=")
        return [line for line in self.text.splitlines() if line.startswith(valid_keys)]

    def Vbat(self):
        for line in self.text.splitlines():
            if line.startswith("Vbat="):
                vbat_value = float(line.split("=")[1].split()[0])  # مقدار عددی Vbat
                if vbat_value == 0.0:
                    return "ُبرق وصل بوده و وضعیت سالن مناسب است"
                else:
                    return "برق قطع است و سرخانه شما غیر فعال می باشد"

    def HUM1(self):
        for line in self.text.splitlines():
            if line.startswith("HUM1="):
                HUM1_value = line.split("=")[1].strip()  # مقدار HUM1 را جدا کنید
                if HUM1_value == 'NC':
                    return "سرخانه شما رطوبتی ندارد"
                else:
                    return f"رطوبت سرخانه شما {HUM1_value} درصد می باشد"

    def TEMP1(self):
        for line in self.text.splitlines():
            if line.startswith("TEMP1="):
                TEMP1_value = float(line.split("=")[1].strip())
                if TEMP1_value < 0:
                    return f"دمای سرخانه زیر صفر شما {TEMP1_value} درجه می باشد"
                else:
                    return f"دمای سرخانه زیر صفر شما افزایش یافته است و {TEMP1_value} درجه می باشد "

    def Credit(self):
        for line in self.text.splitlines():
            if line.startswith("Credit="):
                credit_value = float(line.split("=")[1].strip())
                return f"شارژ سرخانه شما {credit_value} ریال می باشد"

    def general(self):
        respond = ""

        for line in self.text.splitlines():
            if line.startswith("relays="):
                relays_value = line.split("=")[1].strip()
                if relays_value == '0x000':
                    respond = "همه دستگاه های سردخانه خاموش یا در حالت اتومات هستند"
                elif relays_value == '0x001':
                    respond = "کمپرسور و سالن زیر صفر روشن هستند"
                elif relays_value == '0x004':
                    respond = "سیستم در حال دیفراست و برفک زدایی می باشد"
                elif relays_value == '0x008':
                    respond = "سالن بالای صفر روشن می باشد"
                elif relays_value == '0x007':
                    respond = "کلیه قسمت های زیر صفر و بالای صفر روشن و درحال کار می باشند"
                elif relays_value == '0x005':
                    self.defrost = True
                    respond = "سردخانه در حال دیفراست است"

                if line.startswith("inputs="):
                    inputs_value = line.split("=")[1].strip()
                    if self.defrost:
                        return respond
                    elif inputs_value == '0x01':
                        respond =  respond + "همچنین" + "کنترل بار کمپرسور عمل کرده و سرخانه خاموش است"
                    elif inputs_value == '0x02':
                        respond =  respond + "همچنین" + "سیستم با کمبود گاز مواجه شده و کمپرسور خاموش است"
                    elif inputs_value == '0x04':
                        respond =  respond + "همچنین" + "حرارت بالای موتور باعث عملکرد ترمیستور حفاظتی شده و کمپرسور خاموش شده است"
                    elif inputs_value == '0x08':
                        respond =  respond + "همچنین" + "برق ورودی سرخانه نقص دارد و باعث خاموش شدن سردخانه شده است لطفا برای رفع ایراد ورودی برق را چک کنید"
                    elif inputs_value == '0x00':
                        return respond
                    return respond

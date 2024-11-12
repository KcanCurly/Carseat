
class PrintHandler:
    @staticmethod
    def show_banner(banner: str):
        print(f"\n\n====== {banner} ======\n")

    @staticmethod
    def print_props(obj_or_list):       
        if isinstance(obj_or_list, list):
            for obj in obj_or_list:
                for attr, value in vars(obj).items():
                    print(f"  {attr:<30} : {'' if value is None else value}")
                print()
        else:
            for attr, value in vars(obj_or_list).items():
                print(f"  {attr:<30} : {'' if value is None else value}")

    @staticmethod
    def print_kv(obj_or_list):
        if isinstance(obj_or_list, list):
            for item in obj_or_list:
                PrintHandler._print_single_key_value_object(item)
        else:
            PrintHandler._print_single_key_value_object(obj_or_list)

    @staticmethod
    def _print_single_key_value_object(obj):
        if hasattr(obj, 'Key') and hasattr(obj, 'Value'):
            print(f"  {obj.Key:<25} : {obj.Value}")
        else:
            print(f"Invalid object: {obj}")

    @staticmethod
    def print_key_entries(obj_or_list):        
        def print_single_obj(obj):
            attrs = vars(obj)
            for attr, value in attrs.items():
                if isinstance(value, list):
                    for item in value:
                        print(f"    {item}")
                else:
                    print(f"  {value} :")
            print()

        if isinstance(obj_or_list, list):
            for obj in obj_or_list:
                print_single_obj(obj)
        else:
            print_single_obj(obj_or_list)
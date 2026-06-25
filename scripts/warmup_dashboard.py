#!/usr/bin/env python3
"""
仪表盘缓存预热脚本

用法:
  python scripts/warmup_dashboard.py 34              # 预热单个仪表盘
  python scripts/warmup_dashboard.py 34 35 36       # 预热多个仪表盘
  python scripts/warmup_dashboard.py --all          # 预热所有仪表盘
"""
import sys
import traceback

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    # 必须先初始化 Superset 应用，再导入依赖 security_manager 的模块
    from superset.app import create_app

    app = create_app()
    with app.app_context():
        # 应用初始化完成后再导入，避免 security_manager 为 None
        from superset.tasks.cache import dashboard_cache_warmup

        try:
            if "--all" in sys.argv:
                print("预热所有仪表盘...")
                result = dashboard_cache_warmup(None)
            else:
                dashboard_ids = [int(id) for id in sys.argv[1:] if id.isdigit()]
                if not dashboard_ids:
                    print("错误: 请提供有效的仪表盘 ID")
                    sys.exit(1)

                print(f"预热仪表盘: {dashboard_ids}")
                result = dashboard_cache_warmup(dashboard_ids)
        except Exception:
            print("\n预热执行失败，完整堆栈：")
            traceback.print_exc()
            sys.exit(1)

        print("\n预热结果:")
        print(f"  成功: {len(result.get('success', []))}")
        print(f"  失败: {len(result.get('errors', []))}")

        if result.get('errors'):
            print("\n错误详情:")
            for error in result['errors']:
                print(f"  - {error}")

if __name__ == "__main__":
    main()
